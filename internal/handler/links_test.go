package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinkLockOrder(t *testing.T) {
	tests := []struct {
		name       string
		a, b       int
		wantFirst  int32
		wantSecond int32
	}{
		{"already ascending", 1, 2, 1, 2},
		{"descending swaps", 2, 1, 1, 2},
		{"equal ids", 7, 7, 7, 7},
		{"large ids keep order", 41, 2147483647, 41, 2147483647},
		{"large ids swapped", 2147483647, 41, 41, 2147483647},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, second := linkLockOrder(tt.a, tt.b)
			if first != tt.wantFirst || second != tt.wantSecond {
				t.Errorf("linkLockOrder(%d, %d) = (%d, %d), want (%d, %d)",
					tt.a, tt.b, first, second, tt.wantFirst, tt.wantSecond)
			}
		})
	}
}

func TestLinkLockOrder_Deterministic(t *testing.T) {
	// The same pair must always produce the same lock order regardless of
	// argument order — that is what prevents deadlocks between concurrent
	// LinkRequest/LinkRespond calls on the same pair.
	f1, s1 := linkLockOrder(3, 9)
	f2, s2 := linkLockOrder(9, 3)
	if f1 != f2 || s1 != s2 {
		t.Errorf("lock order differs by argument order: (%d,%d) vs (%d,%d)", f1, s1, f2, s2)
	}
	if f1 > s1 {
		t.Errorf("first lock key %d > second %d; must be ascending", f1, s1)
	}
}

// assertLinkErrorEnvelope asserts a link-endpoint failure response uses the
// shared {ok:false, error:"..."} envelope that the client's ApiError surfaces,
// and never the legacy "message" key (which the shared client ignores,
// collapsing every failure into a generic "Request failed").
func assertLinkErrorEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("status = %d, want %d", w.Code, wantStatus)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v (body %q)", err, w.Body.String())
	}
	if ok, _ := resp["ok"].(bool); ok {
		t.Errorf("ok = true in failure response %q", w.Body.String())
	}
	msg, has := resp["error"].(string)
	if !has || msg == "" {
		t.Errorf("failure response missing non-empty 'error' key: %q", w.Body.String())
	}
	if _, hasMessage := resp["message"]; hasMessage {
		t.Errorf("failure response still carries 'message' key: %q", w.Body.String())
	}
}

func TestLinkRequest_FailureUsesErrorKey(t *testing.T) {
	h := &LinksHandler{} // nil pool: only pre-DB validation paths are reachable

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"invalid json", "not json", http.StatusBadRequest},
		{"empty email", `{"email":"  "}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/settings/link/request", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h.LinkRequest(w, r)
			assertLinkErrorEnvelope(t, w, tt.wantStatus)
		})
	}
}

func TestLinkRespond_FailureUsesErrorKey(t *testing.T) {
	h := &LinksHandler{}

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"invalid json", "not json", http.StatusBadRequest},
		{"missing request_id", `{"action":"accept"}`, http.StatusBadRequest},
		{"bad action", `{"request_id":5,"action":"maybe"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/settings/link/respond", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h.LinkRespond(w, r)
			assertLinkErrorEnvelope(t, w, tt.wantStatus)
		})
	}
}

func TestLinkRemove_FailureUsesErrorKey(t *testing.T) {
	h := &LinksHandler{}

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"invalid json", "not json", http.StatusBadRequest},
		{"zero link id", `{"link_id":0}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/settings/link/remove", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h.LinkRemove(w, r)
			assertLinkErrorEnvelope(t, w, tt.wantStatus)
		})
	}
}
