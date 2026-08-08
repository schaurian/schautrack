package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeV1RejectsNulBytes pins #378. A NUL in a text field used to reach
// Postgres, fail with SQLSTATE 22021 and surface as a 500 through dbFail —
// across ten error paths in five handlers, for a request entirely of the
// caller's making.
func TestDecodeV1RejectsNulBytes(t *testing.T) {
	var dst v1CommonTestBody

	for _, body := range []string{
		`{"name":"a\u0000b"}`,
		`{"name":"\u0000"}`,
		`{"name":"trailing\u0000"}`,
	} {
		got := decodeV1(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &dst)
		if got == nil {
			t.Errorf("decodeV1(%s) accepted a NUL byte", body)
			continue
		}
		if got.Status != http.StatusBadRequest {
			t.Errorf("decodeV1(%s) = %d, want 400 (a client mistake, not a server failure)", body, got.Status)
		}
	}

	// A literal NUL byte is not valid JSON at all — encoding/json rejects it as
	// a control character — so it can never reach a decoded string. Pinned so
	// the raw-bytes check above is known to cover every reachable spelling.
	got := decodeV1(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{\"name\":\"a\x00b\"}")), &dst)
	if got == nil || got.Status != http.StatusBadRequest {
		t.Errorf("a literal NUL in the body = %v, want a 400", got)
	}

	// The escape must not be confused with harmless neighbours.
	for _, body := range []string{`{"name":"\u0041"}`, `{"name":"u0000"}`, `{"name":"0000"}`} {
		if got := decodeV1(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &dst); got != nil {
			t.Errorf("decodeV1(%s) = %v, want accepted", body, got)
		}
	}
}
