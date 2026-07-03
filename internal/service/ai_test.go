package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestEncryptDecryptApiKey(t *testing.T) {
	// 32-byte key in hex (64 hex chars)
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := "sk-test-api-key-12345"

	encrypted := EncryptApiKey(plaintext, secret)
	if encrypted == "" {
		t.Fatal("encryption returned empty string")
	}

	decrypted := DecryptApiKey(encrypted, secret)
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptApiKeyEmptyInputs(t *testing.T) {
	if EncryptApiKey("", "abc") != "" {
		t.Error("expected empty for empty plaintext")
	}
	if EncryptApiKey("test", "") != "" {
		t.Error("expected empty for empty secret")
	}
}

func TestDecryptApiKeyInvalid(t *testing.T) {
	if DecryptApiKey("not:valid:data", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") != "" {
		t.Error("expected empty for invalid ciphertext")
	}
}

func TestDecryptApiKeyWrongKey(t *testing.T) {
	secret1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secret2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	encrypted := EncryptApiKey("test-key", secret1)
	decrypted := DecryptApiKey(encrypted, secret2)
	if decrypted != "" {
		t.Error("expected empty for wrong key")
	}
}

// TestCallAIProvider_TokenLimitParam pins the token-limit parameter for each
// provider: OpenAI requires max_completion_tokens (gpt-5/o-series rejected the
// legacy max_tokens), while Anthropic still uses max_tokens. Regression-guards
// against a future "unify the param name" mistake that would break one of them.
func TestCallAIProvider_TokenLimitParam(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		path     string
		// JSON body to return so parseAIResponse succeeds and the test reaches the assertions.
		response string
		assert   func(t *testing.T, body map[string]any)
	}{
		{
			name:     "openai uses max_completion_tokens",
			provider: "openai",
			path:     "/chat/completions",
			response: `{"choices":[{"message":{"content":"{\"calories\":100,\"food\":\"apple\",\"confidence\":\"high\",\"macros\":{}}"}}]}`,
			assert: func(t *testing.T, body map[string]any) {
				if _, ok := body["max_tokens"]; ok {
					t.Errorf("openai request must not set max_tokens (deprecated for gpt-5/o-series)")
				}
				v, ok := body["max_completion_tokens"]
				if !ok {
					t.Fatalf("openai request missing max_completion_tokens; body keys: %v", keys(body))
				}
				if n, _ := v.(float64); n != 1000 {
					t.Errorf("max_completion_tokens = %v, want 1000", v)
				}
			},
		},
		{
			name:     "claude uses max_tokens",
			provider: "claude",
			path:     "/messages",
			response: `{"content":[{"text":"{\"calories\":100,\"food\":\"apple\",\"confidence\":\"high\",\"macros\":{}}"}]}`,
			assert: func(t *testing.T, body map[string]any) {
				if _, ok := body["max_completion_tokens"]; ok {
					t.Errorf("claude request must not set max_completion_tokens (Anthropic uses max_tokens)")
				}
				v, ok := body["max_tokens"]
				if !ok {
					t.Fatalf("claude request missing max_tokens")
				}
				if n, _ := v.(float64); n != 1000 {
					t.Errorf("max_tokens = %v, want 1000", v)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
				}
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &captured); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			_, err := CallAIProvider(context.Background(), tt.provider, "test-key", srv.URL, "Zg==", "image/jpeg", "describe", "test-model")
			if err != nil {
				t.Fatalf("CallAIProvider: %v", err)
			}
			tt.assert(t, captured)
		})
	}
}

// TestCallAIProvider_ContextCancellation guards the fix for the request
// context being ignored: when the caller cancels (e.g. the user aborts the
// HTTP request), the upstream AI call must return promptly instead of
// running for the full 30-60s provider timeout.
func TestCallAIProvider_ContextCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // block until the test tears down
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := CallAIProvider(ctx, "openai", "test-key", srv.URL, "Zg==", "image/jpeg", "describe", "test-model")
		done <- err
	}()

	// Give the request a moment to reach the blocking server, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error after context cancellation, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled in the chain", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CallAIProvider did not return promptly after context cancellation")
	}
}

// TestCallAIProvider_UpstreamErrorType pins that non-2xx upstream responses
// yield a typed *AIProviderError carrying the status code and body, so
// handlers can log the details while sending clients a sanitized message.
func TestCallAIProvider_UpstreamErrorType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"quota exceeded for org acme-internal"}`))
	}))
	defer srv.Close()

	_, err := CallAIProvider(context.Background(), "openai", "test-key", srv.URL, "Zg==", "image/jpeg", "describe", "test-model")
	if err == nil {
		t.Fatal("expected error for 429 upstream response")
	}

	var provErr *AIProviderError
	if !errors.As(err, &provErr) {
		t.Fatalf("error = %T (%v), want *AIProviderError", err, err)
	}
	if provErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want %d", provErr.StatusCode, http.StatusTooManyRequests)
	}
	if !strings.Contains(provErr.Body, "quota exceeded") {
		t.Errorf("Body = %q, want upstream body preserved for logging", provErr.Body)
	}
	// Error() keeps the details for server-side logs.
	if !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("Error() = %q, want status and body for logging", err.Error())
	}
}

// TestAIUsageFromScan guards the GetAIUsageToday fix: only a missing row maps
// to (0, nil); real database errors must be propagated, not swallowed.
func TestAIUsageFromScan(t *testing.T) {
	if n, err := aiUsageFromScan(7, nil); n != 7 || err != nil {
		t.Errorf("aiUsageFromScan(7, nil) = (%d, %v), want (7, nil)", n, err)
	}
	if n, err := aiUsageFromScan(0, pgx.ErrNoRows); n != 0 || err != nil {
		t.Errorf("aiUsageFromScan(0, ErrNoRows) = (%d, %v), want (0, nil)", n, err)
	}
	sentinel := errors.New("connection refused")
	if _, err := aiUsageFromScan(0, sentinel); !errors.Is(err, sentinel) {
		t.Errorf("aiUsageFromScan(0, sentinel) err = %v, want sentinel propagated", err)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
