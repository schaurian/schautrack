package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ReadOptionalJSON separates the two cases the handlers used to conflate: a
// body the caller legitimately omitted, and a body the caller sent that does
// not parse. Dropping the error treated both as "zero value, carry on", which
// is why POST /api/todos/toggle-enabled with a broken body answered 200 and
// silently DISABLED the user's todos — the decode failed, Enabled stayed nil,
// and nil is not true.
func TestReadOptionalJSONAcceptsAnAbsentBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"no body at all", ""},
		{"whitespace only", "   \n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dst struct {
				Enabled any `json:"enabled"`
			}
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			if err := ReadOptionalJSON(r, &dst); err != nil {
				t.Fatalf("ReadOptionalJSON(%q) = %v, want nil — an omitted body is legitimate", tc.body, err)
			}
			if dst.Enabled != nil {
				t.Errorf("Enabled = %v, want the zero value untouched", dst.Enabled)
			}
		})
	}
}

func TestReadOptionalJSONRejectsAMalformedBody(t *testing.T) {
	for _, body := range []string{
		`{`,
		`{"enabled":}`,
		`not json at all`,
		`{"enabled":true}}`,
		`[1,2,3`,
	} {
		t.Run(body, func(t *testing.T) {
			var dst struct {
				Enabled any `json:"enabled"`
			}
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			if err := ReadOptionalJSON(r, &dst); err == nil {
				t.Fatalf("ReadOptionalJSON(%q) = nil; a malformed body must be an error, not a "+
					"silent zero value — that is what turned a broken request into a feature toggle", body)
			}
		})
	}
}

func TestReadOptionalJSONDecodesAWellFormedBody(t *testing.T) {
	var dst struct {
		Enabled any `json:"enabled"`
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"enabled":true}`)))
	if err := ReadOptionalJSON(r, &dst); err != nil {
		t.Fatalf("ReadOptionalJSON: %v", err)
	}
	if dst.Enabled != true {
		t.Errorf("Enabled = %v, want true", dst.Enabled)
	}
}
