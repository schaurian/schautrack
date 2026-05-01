package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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

			_, err := CallAIProvider(tt.provider, "test-key", srv.URL, "Zg==", "image/jpeg", "describe", "test-model")
			if err != nil {
				t.Fatalf("CallAIProvider: %v", err)
			}
			tt.assert(t, captured)
		})
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
