package middleware

import (
	"mime"
	"net/http"
	"strings"

	"github.com/klauspost/compress/gzhttp"
)

// compressMinSize is the smallest JSON body worth encoding. Below roughly a
// kilobyte gzip's header and trailer outweigh what it saves (a 68-byte
// {"ok":true,...} grows), so those go out as they are.
const compressMinSize = 1024

// isJSON reports whether a Content-Type is JSON: application/json or any
// structured-syntax +json type, such as the v1 API's application/problem+json
// errors and its application/openapi+json document.
func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

// compressJSON is built once: gzhttp.NewWrapper only fails on invalid
// options, which these constants are not.
var compressJSON = func() func(http.Handler) http.HandlerFunc {
	wrap, err := gzhttp.NewWrapper(
		gzhttp.ContentTypeFilter(isJSON),
		gzhttp.MinSize(compressMinSize),
		gzhttp.CompressionLevel(5),
		// gzip only, the encoding the static bundle already uses.
		gzhttp.EnableZstd(false),
	)
	if err != nil {
		panic(err)
	}
	return wrap
}()

// CompressJSON gzip-encodes JSON responses of at least compressMinSize bytes
// for clients that send Accept-Encoding: gzip.
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
// JSON (application/json and the +json types). The SSE stream (text/event-stream), HTML, CSS and the
// static files — which carry their own Content-Encoding by the time they reach
// this writer — pass through untouched. That content-type gate is what keeps
// SSE working: an event-stream wrapped in gzip would be buffered by the
// compressor and never reach the browser event by event.
//
// BREACH needs a secret and attacker-chosen input in the same compressed
// response, plus a cross-site attacker able to drive credentialed requests and
// observe their sizes. The session cookie is SameSite=Lax, so cross-site
// subresource requests carry no session, and the v1 API authenticates with a
// bearer token that a third-party page cannot attach.
func CompressJSON(next http.Handler) http.Handler {
	return compressJSON(next)
}
