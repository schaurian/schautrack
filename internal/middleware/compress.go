package middleware

import (
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// CompressJSON gzip/deflate-encodes JSON responses for clients that send
// Accept-Encoding.
//
// The SPA file server already compresses the static bundle; the API did not,
// so every dashboard load, saved-foods list and account export crossed the
// network at full size — on the Android WebView over a mobile link that is
// where the bytes are. Measured against a three-year account: /api/dashboard
// 13.0 KB -> 1.9 KB, /api/saved-foods (300 foods) 62 KB -> 5.0 KB, the account
// export 1.37 MB -> 0.17 MB, for about a millisecond of server time on the first
// two.
//
// It is gated on the response Content-Type, so it only ever touches
// application/json. The SSE stream (text/event-stream) and the static files,
// which carry their own Content-Encoding by the time they reach this writer,
// pass through untouched. That content-type gate is what keeps SSE working:
// an event-stream wrapped in gzip would be buffered by the compressor and
// never reach the browser event by event.
//
// BREACH needs a secret and attacker-chosen input in the same compressed
// response, plus a cross-site attacker able to drive credentialed requests and
// observe their sizes. The session cookie is SameSite=Lax, so cross-site
// subresource requests carry no session, and the v1 API authenticates with a
// bearer token that a third-party page cannot attach.
func CompressJSON(next http.Handler) http.Handler {
	return chimw.Compress(5, "application/json")(next)
}
