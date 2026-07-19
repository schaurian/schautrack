package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// TestResolveAIConfig guards the three-tier key hierarchy fix: only a global
// KEY disables personal keys. A provider-only global config (no global key)
// must fall back to the user's personal key/model.
func TestResolveAIConfig(t *testing.T) {
	tests := []struct {
		name string
		in   aiConfigInputs
		want resolvedAIConfig
	}{
		{
			name: "global key pins global config and ignores personal key",
			in: aiConfigInputs{
				GlobalKey: "gk", GlobalEndpoint: "https://proxy.example", GlobalModel: "gpt-4o",
				UserKey: "uk", UserModel: "user-model",
			},
			want: resolvedAIConfig{
				APIKey: "gk", Endpoint: "https://proxy.example", Model: "gpt-4o", UsingGlobalKey: true,
			},
		},
		{
			name: "provider-only global config falls back to personal key (regression: #141)",
			in: aiConfigInputs{
				GlobalKey: "", GlobalEndpoint: "", GlobalModel: "",
				UserKey: "uk", UserModel: "user-model",
			},
			want: resolvedAIConfig{
				APIKey: "uk", Endpoint: "", Model: "user-model", UsingGlobalKey: false,
			},
		},
		{
			name: "personal key with global model as fallback",
			in: aiConfigInputs{
				GlobalKey: "", GlobalModel: "gpt-4o-mini",
				UserKey: "uk", UserModel: "",
			},
			want: resolvedAIConfig{
				APIKey: "uk", Model: "gpt-4o-mini", UsingGlobalKey: false,
			},
		},
		{
			name: "personal key path still uses global endpoint (ollama)",
			in: aiConfigInputs{
				GlobalKey: "", GlobalEndpoint: "http://ollama.internal:11434/v1", GlobalModel: "gemma3:12b",
				UserKey: "", UserModel: "",
			},
			want: resolvedAIConfig{
				APIKey: "", Endpoint: "http://ollama.internal:11434/v1", Model: "gemma3:12b", UsingGlobalKey: false,
			},
		},
		{
			name: "global key without global model does not borrow the user model",
			in: aiConfigInputs{
				GlobalKey: "gk", GlobalModel: "",
				UserKey: "uk", UserModel: "user-model",
			},
			want: resolvedAIConfig{
				APIKey: "gk", Model: "", UsingGlobalKey: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAIConfig(tt.in)
			if got != tt.want {
				t.Errorf("resolveAIConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestAIClientErrorMessage guards the error-sanitization fix: the message sent
// to clients must never contain the upstream response body or the (possibly
// internal) endpoint URL.
func TestAIClientErrorMessage(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		want       string
		mustNotHold []string
	}{
		{
			name: "url.Error must not leak internal endpoint",
			err: fmt.Errorf("AI request failed: %w", &url.Error{
				Op:  "Post",
				URL: "http://ollama.internal.lan:11434/v1/chat/completions",
				Err: errors.New("connection refused"),
			}),
			want:        "AI estimation failed, please try again.",
			mustNotHold: []string{"ollama.internal.lan", "11434", "connection refused"},
		},
		{
			name:        "provider 500 must not leak upstream body",
			err:         &service.AIProviderError{StatusCode: 500, Body: `{"error":"secret internal details"}`},
			want:        "AI estimation failed, please try again.",
			mustNotHold: []string{"secret internal details"},
		},
		{
			name:        "provider 429 maps to coarse rate-limit category",
			err:         &service.AIProviderError{StatusCode: 429, Body: "org quota details"},
			want:        "The AI provider is rate limiting requests. Please try again later.",
			mustNotHold: []string{"org quota details"},
		},
		{
			name:        "provider 401 maps to coarse auth category",
			err:         &service.AIProviderError{StatusCode: 401, Body: "invalid api key sk-abc123"},
			want:        "The AI provider rejected the configured API key.",
			mustNotHold: []string{"sk-abc123"},
		},
		{
			name:        "provider 403 maps to coarse auth category",
			err:         &service.AIProviderError{StatusCode: 403, Body: "forbidden"},
			want:        "The AI provider rejected the configured API key.",
			mustNotHold: []string{"forbidden"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aiClientErrorMessage(tt.err)
			if got != tt.want {
				t.Errorf("aiClientErrorMessage() = %q, want %q", got, tt.want)
			}
			for _, leak := range tt.mustNotHold {
				if strings.Contains(got, leak) {
					t.Errorf("message %q leaks %q", got, leak)
				}
			}
		})
	}
}

// TestEstimate_OversizedBodyReturns413 guards the ReadJSONLimit fix: a body
// over the AI route limit must map to 413 "Image too large", not a generic
// 400 from silent truncation.
func TestEstimate_OversizedBodyReturns413(t *testing.T) {
	h := &AIHandler{}
	huge := `{"image":"data:image/jpeg;base64,` + strings.Repeat("A", maxAIRequestBytes) + `"}`
	r := httptest.NewRequest("POST", "/api/ai/estimate", strings.NewReader(huge))
	w := httptest.NewRecorder()

	h.Estimate(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "Image too large") {
		t.Errorf("error = %q, want message about image size", msg)
	}
}

// TestEstimate_ImageOver14MBReturns413 verifies the previously-unreachable
// 14MB image check now triggers: an image field over 14MB inside a body under
// the 15MB route limit must return 413.
func TestEstimate_ImageOver14MBReturns413(t *testing.T) {
	h := &AIHandler{}
	img := "data:image/jpeg;base64," + strings.Repeat("A", maxImageBase64Bytes)
	body := `{"image":"` + img + `"}`
	if int64(len(body)) > maxAIRequestBytes {
		t.Fatalf("test body (%d bytes) exceeds the route limit; adjust the test", len(body))
	}
	r := httptest.NewRequest("POST", "/api/ai/estimate", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Estimate(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "Image too large") {
		t.Errorf("error = %q, want message about image size", msg)
	}
}

// TestEstimate_InvalidJSONReturns400 pins the non-oversize error path.
func TestEstimate_InvalidJSONReturns400(t *testing.T) {
	h := &AIHandler{}
	r := httptest.NewRequest("POST", "/api/ai/estimate", strings.NewReader(`{not json`))
	w := httptest.NewRecorder()

	h.Estimate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
