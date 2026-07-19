package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// openaiEnvelope wraps a raw model output string in the OpenAI/Ollama
// chat-completions response shape, letting each test case state the model's
// content verbatim while json.Marshal handles the escaping.
func openaiEnvelope(content string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": content}}},
	})
	return string(b)
}

// claudeEnvelope wraps a raw model output string in the Anthropic messages
// response shape.
func claudeEnvelope(text string) string {
	b, _ := json.Marshal(map[string]any{
		"content": []map[string]any{{"text": text}},
	})
	return string(b)
}

// TestParseAIResponse exercises parseAIResponse directly across the edge cases
// that were previously only reached indirectly through CallAIProvider: markdown-
// fenced and prose-wrapped JSON, the NO_FOOD_DETECTED sentinel, empty/absent
// content, malformed provider envelopes, and the first-'{'/last-'}' slicing
// weaknesses (two objects, trailing brace). These assertions pin *current*
// behavior — including the known-fragile brace slicing — so a future refactor
// becomes a deliberate, visible change rather than a silent regression.
func TestParseAIResponse(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		body     string
		want     *AIResult // expected result when wantErr == ""
		wantErr  string    // substring the error must contain; "" => expect success
	}{
		// --- happy paths ---
		{
			name:     "openai plain json",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":250,"food":"banana","confidence":"high","macros":{"protein":3}}`),
			want:     &AIResult{Calories: 250, Food: "banana", Confidence: "high", Macros: map[string]int{"protein": 3}},
		},
		{
			name:     "claude plain json",
			provider: "claude",
			body:     claudeEnvelope(`{"calories":300,"food":"toast","confidence":"medium"}`),
			want:     &AIResult{Calories: 300, Food: "toast", Confidence: "medium"},
		},
		{
			name:     "ollama uses the choices envelope",
			provider: "ollama",
			body:     openaiEnvelope(`{"calories":90,"food":"celery"}`),
			want:     &AIResult{Calories: 90, Food: "celery"},
		},
		{
			name:     "unknown provider falls back to the choices envelope",
			provider: "gemini",
			body:     openaiEnvelope(`{"calories":42,"food":"olive"}`),
			want:     &AIResult{Calories: 42, Food: "olive"},
		},
		{
			name:     "markdown-fenced json is unwrapped by brace slicing",
			provider: "openai",
			body:     openaiEnvelope("```json\n{\"calories\":100,\"food\":\"apple\"}\n```"),
			want:     &AIResult{Calories: 100, Food: "apple"},
		},
		{
			name:     "prose-wrapped json is extracted",
			provider: "openai",
			body:     openaiEnvelope(`Sure! Here is the estimate: {"calories":55,"food":"grape"} Hope that helps.`),
			want:     &AIResult{Calories: 55, Food: "grape"},
		},
		{
			name:     "missing food field defaults to empty string",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":120}`),
			want:     &AIResult{Calories: 120},
		},
		{
			name:     "unknown json fields are ignored",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":75,"food":"kiwi","serving":"1 cup","extra":true}`),
			want:     &AIResult{Calories: 75, Food: "kiwi"},
		},
		{
			name:     "out-of-range calories pass through unclamped (range checks live in the caller)",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":999999,"food":"cake"}`),
			want:     &AIResult{Calories: 999999, Food: "cake"},
		},
		{
			name:     "zero calories with non-sentinel food is a valid result",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":0,"food":"Water"}`),
			want:     &AIResult{Calories: 0, Food: "Water"},
		},

		// --- NO_FOOD_DETECTED sentinel ---
		{
			name:     "no-food sentinel returns NO_FOOD_DETECTED",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":0,"food":"No food detected"}`),
			wantErr:  "NO_FOOD_DETECTED",
		},
		{
			name:     "sentinel food with non-zero calories is not treated as no-food",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":10,"food":"No food detected"}`),
			want:     &AIResult{Calories: 10, Food: "No food detected"},
		},

		// --- empty / absent content ---
		{
			name:     "empty content string",
			provider: "openai",
			body:     openaiEnvelope(""),
			wantErr:  "empty AI response",
		},
		{
			name:     "empty choices array",
			provider: "openai",
			body:     `{"choices":[]}`,
			wantErr:  "empty AI response",
		},
		{
			name:     "absent choices field",
			provider: "openai",
			body:     `{}`,
			wantErr:  "empty AI response",
		},
		{
			name:     "empty claude content array",
			provider: "claude",
			body:     `{"content":[]}`,
			wantErr:  "empty AI response",
		},
		{
			name:     "whitespace-only content is not valid JSON",
			provider: "openai",
			body:     openaiEnvelope("   \n\t "),
			wantErr:  "failed to parse AI JSON",
		},

		// --- malformed provider envelopes ---
		{
			name:     "malformed openai envelope",
			provider: "openai",
			body:     `not json at all`,
			wantErr:  "failed to parse AI response",
		},
		{
			name:     "malformed claude envelope",
			provider: "claude",
			body:     `<html>gateway error</html>`,
			wantErr:  "failed to parse Claude response",
		},

		// --- malformed inner JSON ---
		{
			name:     "content with no JSON object",
			provider: "openai",
			body:     openaiEnvelope("I can't identify any food in this image."),
			wantErr:  "failed to parse AI JSON",
		},
		{
			name:     "invalid inner JSON (trailing comma)",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":100,"food":"x",}`),
			wantErr:  "failed to parse AI JSON",
		},
		{
			name:     "fractional macro rejected by int map",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":100,"food":"x","macros":{"protein":3.5}}`),
			wantErr:  "failed to parse AI JSON",
		},

		// --- documented first-'{'/last-'}' slicing weaknesses (pinned, not fixed) ---
		{
			name:     "two JSON objects break brace slicing (known weakness)",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":100,"food":"a"} {"calories":200,"food":"b"}`),
			wantErr:  "failed to parse AI JSON",
		},
		{
			name:     "trailing brace breaks slicing (known weakness)",
			provider: "openai",
			body:     openaiEnvelope(`{"calories":100,"food":"a"}}`),
			wantErr:  "failed to parse AI JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAIResponse(tt.provider, []byte(tt.body))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseAIResponse() error = nil, want error containing %q (got result %+v)", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseAIResponse() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				if got != nil {
					t.Errorf("parseAIResponse() result = %+v, want nil on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAIResponse() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAIResponse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
