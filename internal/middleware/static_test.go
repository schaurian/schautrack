package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsStaticAsset(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		// Static assets that should bypass the auth middlewares.
		{"vite asset js", http.MethodGet, "/assets/index-DOugxfrc.js", true},
		{"vite asset css", http.MethodGet, "/assets/index-abc123.css", true},
		{"vite asset nested", http.MethodGet, "/assets/fonts/noto.woff2", true},
		{"root favicon 32", http.MethodGet, "/favicon-32.png", true},
		{"root favicon 16", http.MethodGet, "/favicon-16.png", true},
		{"apple touch icon", http.MethodGet, "/apple-touch-icon.png", true},
		{"logo", http.MethodGet, "/logo.png", true},
		{"og image jpg", http.MethodGet, "/og-image.jpg", true},
		{"oidc logo svg", http.MethodGet, "/oidc-logos/google.svg", true},
		{"imprint svg", http.MethodGet, "/imprint/address.svg", true},
		{"uppercase extension", http.MethodGet, "/LOGO.PNG", true},
		{"head request for asset", http.MethodHead, "/assets/index-DOugxfrc.js", true},

		// Dynamic / authenticated routes that must keep the full pipeline.
		{"api dashboard", http.MethodGet, "/api/dashboard", false},
		{"api me", http.MethodGet, "/api/me", false},
		{"api asset-looking path", http.MethodGet, "/api/report.png", false},
		{"sse stream", http.MethodGet, "/events/entries", false},
		{"spa root", http.MethodGet, "/", false},
		{"spa client route", http.MethodGet, "/dashboard", false},
		{"index html not classified", http.MethodGet, "/index.html", false},
		{"top-level overview", http.MethodGet, "/overview", false},
		{"barcode lookup", http.MethodGet, "/api/barcode/12345", false},

		// Non-GET/HEAD methods are never static, even for asset-looking paths.
		{"post to asset path", http.MethodPost, "/assets/index.js", false},
		{"post to logo", http.MethodPost, "/logo.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			if got := IsStaticAsset(r); got != tt.want {
				t.Errorf("IsStaticAsset(%s %s) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestSkipStaticAssets(t *testing.T) {
	// Marker middleware records whether it ran and forwards the request.
	newMarker := func(ran *bool) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				*ran = true
				next.ServeHTTP(w, r)
			})
		}
	}

	t.Run("bypasses wrapped middleware for static asset", func(t *testing.T) {
		var mwRan, handlerRan bool
		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerRan = true })
		h := SkipStaticAssets(newMarker(&mwRan))(final)

		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))

		if mwRan {
			t.Error("wrapped middleware ran for a static asset request; want bypass")
		}
		if !handlerRan {
			t.Error("downstream handler did not run for a static asset request")
		}
	})

	t.Run("runs wrapped middleware for dynamic route", func(t *testing.T) {
		var mwRan, handlerRan bool
		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerRan = true })
		h := SkipStaticAssets(newMarker(&mwRan))(final)

		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))

		if !mwRan {
			t.Error("wrapped middleware did not run for a dynamic route; auth would be skipped")
		}
		if !handlerRan {
			t.Error("downstream handler did not run for a dynamic route")
		}
	})
}
