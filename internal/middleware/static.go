package middleware

import (
	"net/http"
	"path"
	"strings"
)

// staticAssetExts are file extensions for assets the SPA file server returns
// verbatim (Vite build output, favicons, logos, fonts, imprint SVGs). None of
// these paths are handled by a route that reads the session or the current
// user, so bypassing the auth middlewares for them is safe. Notably absent are
// generic extensions like .json / .html that could collide with dynamic
// content — being conservative here only forgoes an optimization, never
// weakens auth.
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".avif": true, ".ico": true, ".svg": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".webmanifest": true,
}

// IsStaticAsset reports whether r is a safe-to-bypass request for a static
// asset — Vite build output under /assets/, or a root file with a static
// extension (favicons, logos, fonts). Such requests are served by the SPA file
// server (or the settings-only imprint SVG handlers) and never consult the
// session or the current user.
//
// Only GET/HEAD requests match, and never anything under /api/ or /events/, so
// every authenticated API route and the SSE stream keep their full session +
// user pipeline. Misclassifying here can only skip an optimization, not expose
// a protected route: RequireLogin/RequireAdmin still run on their own groups
// and would reject a request that reached them without a user.
func IsStaticAsset(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/events/") {
		return false
	}
	if strings.HasPrefix(p, "/assets/") {
		return true
	}
	return staticAssetExts[strings.ToLower(path.Ext(p))]
}

// SkipStaticAssets wraps a middleware so it is bypassed for static asset
// requests (see IsStaticAsset). Static files are served without ever reading
// the session or the current user, so running the session SELECT + the
// full 19-column users SELECT for each one just multiplies DB round trips per
// page view — a single dashboard load fans out to ~a dozen such requests.
//
// Non-static requests run the wrapped middleware unchanged, preserving the
// exact ordering and behavior of the original chain.
func SkipStaticAssets(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsStaticAsset(r) {
				next.ServeHTTP(w, r)
				return
			}
			wrapped.ServeHTTP(w, r)
		})
	}
}
