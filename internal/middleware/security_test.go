package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// wantCSP is the Content-Security-Policy this application serves, pinned
// byte-for-byte.
//
// The point of an exact-match assertion (rather than a set of "contains"
// checks) is that the CSP is the last line of defence against an injected
// script, and it is the kind of header that gets quietly widened to make a
// third-party library work. With this test in place, widening it is a visible
// diff in a security test that a reviewer has to approve on purpose, instead of
// a one-word edit in a middleware nobody reads.
const wantCSP = "default-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"font-src 'self'; " +
	"img-src 'self' data: blob:; " +
	"script-src 'self'"

// wantSecurityHeaders is the full header set, name → exact value.
var wantSecurityHeaders = map[string]string{
	"Content-Security-Policy":           wantCSP,
	"Cross-Origin-Opener-Policy":        "same-origin",
	"Cross-Origin-Resource-Policy":      "same-origin",
	"Origin-Agent-Cluster":              "?1",
	"Referrer-Policy":                   "no-referrer",
	"Strict-Transport-Security":         "max-age=15552000; includeSubDomains",
	"X-Content-Type-Options":            "nosniff",
	"X-DNS-Prefetch-Control":            "off",
	"X-Download-Options":                "noopen",
	"X-Frame-Options":                   "SAMEORIGIN",
	"X-Permitted-Cross-Domain-Policies": "none",
	"X-XSS-Protection":                  "0",
}

// serveThrough runs one request through SecurityHeaders and returns the
// recorder, so each test can pick its own downstream behaviour.
func serveThrough(next http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	SecurityHeaders(next).ServeHTTP(rec, r)
	return rec
}

// cspDirectives splits a policy into directive name → source list.
func cspDirectives(policy string) map[string][]string {
	out := make(map[string][]string)
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = fields[1:]
	}
	return out
}

func TestSecurityHeadersCSPIsExact(t *testing.T) {
	rec := serveThrough(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("Content-Security-Policy")
	if got != wantCSP {
		t.Errorf("Content-Security-Policy changed.\n got: %s\nwant: %s\n\n"+
			"If this change is deliberate, update wantCSP in this test in the same commit — "+
			"and read the unsafe-eval assertions below before you do.", got, wantCSP)
	}
}

// TestSecurityHeadersScriptSrcHasNoUnsafeDirectives is the assertion CLAUDE.md's
// "never use eval() or Function() in client-side code" rule depends on.
//
// client/src/lib/mathParser.ts exists precisely because 'unsafe-eval' is absent
// here. Until this test existed, the rule was a comment: relaxing the CSP to
// make some library work would have broken nothing and failed nothing, and the
// hand-written parser would have become dead weight guarding a door that was
// already open.
func TestSecurityHeadersScriptSrcHasNoUnsafeDirectives(t *testing.T) {
	rec := serveThrough(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		httptest.NewRequest(http.MethodGet, "/", nil))
	dirs := cspDirectives(rec.Header().Get("Content-Security-Policy"))

	scriptSrc, ok := dirs["script-src"]
	if !ok {
		t.Fatal("the policy has no script-src directive; scripts would fall back to default-src")
	}
	for _, src := range scriptSrc {
		switch src {
		case "'unsafe-eval'":
			t.Errorf("script-src contains 'unsafe-eval'. This re-enables eval()/Function() in the "+
				"browser and makes client/src/lib/mathParser.ts pointless. script-src = %v", scriptSrc)
		case "'unsafe-inline'":
			t.Errorf("script-src contains 'unsafe-inline'. Inline <script> becomes executable and the "+
				"CSP stops being an XSS mitigation. script-src = %v", scriptSrc)
		case "'unsafe-hashes'", "*", "data:", "blob:":
			t.Errorf("script-src contains %q, which widens the script origin set. script-src = %v", src, scriptSrc)
		}
	}

	// 'unsafe-inline' is legitimate for styles (Svelte emits inline style
	// attributes) and nowhere else. 'unsafe-eval' is legitimate nowhere.
	for name, sources := range dirs {
		for _, src := range sources {
			if src == "'unsafe-eval'" {
				t.Errorf("%s contains 'unsafe-eval'; no directive in this policy may", name)
			}
			if src == "'unsafe-inline'" && name != "style-src" {
				t.Errorf("%s contains 'unsafe-inline'; only style-src may", name)
			}
		}
	}

	// default-src is the fallback for every directive that is not listed
	// (connect-src, frame-src, object-src, …), so it must stay at 'self'.
	if want := []string{"'self'"}; len(dirs["default-src"]) != 1 || dirs["default-src"][0] != want[0] {
		t.Errorf("default-src = %v, want %v — it is the fallback for every unlisted directive",
			dirs["default-src"], want)
	}
}

func TestSecurityHeadersTable(t *testing.T) {
	rec := serveThrough(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), httptest.NewRequest(http.MethodGet, "/api/dashboard", nil))

	for name, want := range wantSecurityHeaders {
		t.Run(name, func(t *testing.T) {
			if got := rec.Header().Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		})
	}
}

// TestSecurityHeadersHSTSIsAtLeastSixMonths guards the one header whose value
// is a number that means something: browsers only accept a site into the HSTS
// preload list at max-age >= 31536000, and anything under a few months makes
// the header close to decorative.
func TestSecurityHeadersHSTSIsAtLeastSixMonths(t *testing.T) {
	rec := serveThrough(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		httptest.NewRequest(http.MethodGet, "/", nil))

	hsts := rec.Header().Get("Strict-Transport-Security")
	if !strings.HasPrefix(hsts, "max-age=15552000") {
		t.Errorf("Strict-Transport-Security = %q; the max-age was changed from 15552000 (180 days). "+
			"Lowering it shortens the window in which a browser refuses plaintext.", hsts)
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("Strict-Transport-Security = %q, want includeSubDomains", hsts)
	}
}

// TestSecurityHeadersOnEveryResponseKind covers the failure mode where headers
// are set only on the happy path. A 500 rendered into an HTML page, a 404, a
// redirect and a static asset are all places an injected script could land, so
// they need the same policy as a 200.
func TestSecurityHeadersOnEveryResponseKind(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		handler http.HandlerFunc
	}{
		{"200 with body", "/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"ok":true}`))
		}},
		{"500 error response", "/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}},
		{"404 not found", "/nope", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}},
		{"401 unauthorized", "/api/tokens", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}},
		{"302 redirect", "/login", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}},
		{"static JS asset", "/assets/index-DOugxfrc.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte("console.log(1)"))
		}},
		{"index.html", "/index.html", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<!doctype html>"))
		}},
		{"handler that writes nothing at all", "/", func(w http.ResponseWriter, r *http.Request) {}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveThrough(tc.handler, httptest.NewRequest(http.MethodGet, tc.path, nil))
			for name, want := range wantSecurityHeaders {
				if got := rec.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

// TestSecurityHeadersSurviveStaticAssetShortcut pins the interaction with the
// middleware order in cmd/server/main.go: SecurityHeaders is mounted ABOVE
// SkipStaticAssets, so the session/user shortcut for asset requests must not
// also skip the policy. Swapping those two lines is an easy mistake and would
// silently ship unprotected assets.
func TestSecurityHeadersSurviveStaticAssetShortcut(t *testing.T) {
	skipped := false
	authLike := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			skipped = false
			next.ServeHTTP(w, r)
		})
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("asset"))
	})

	// Same order as main.go: SecurityHeaders → SkipStaticAssets(auth).
	h := SecurityHeaders(SkipStaticAssets(authLike)(final))

	skipped = true
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/index-DOugxfrc.js", nil))

	if !skipped {
		t.Fatal("test setup: the asset request did not take the SkipStaticAssets shortcut")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("static asset served without the CSP: got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("static asset served without X-Content-Type-Options: got %q", got)
	}
}

// TestSecurityHeadersCallsNext is the trivial-but-necessary check that the
// middleware is not a dead end.
func TestSecurityHeadersCallsNext(t *testing.T) {
	called := false
	rec := serveThrough(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}), httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("downstream handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d — the middleware must not write a status of its own",
			rec.Code, http.StatusTeapot)
	}
}
