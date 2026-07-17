package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"schautrack/internal/config"
)

func TestAssetLinks_UnconfiguredReturns404(t *testing.T) {
	// No fingerprint configured -> endpoint is disabled and must 404 rather
	// than serve a statement with an empty/placeholder fingerprint.
	cfg := &config.Config{AndroidPackageName: "to.schauer.schautrack"}
	h := AssetLinks(cfg)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/assetlinks.json", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestAssetLinks_ConfiguredServesValidStatement(t *testing.T) {
	fp := "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
	cfg := &config.Config{
		AndroidPackageName:      "to.schauer.schautrack",
		AndroidCertFingerprints: []string{fp},
	}
	h := AssetLinks(cfg)

	r := httptest.NewRequest(http.MethodGet, "/.well-known/assetlinks.json", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Must be a valid Digital Asset Links array with the expected shape.
	var stmts []struct {
		Relation []string `json:"relation"`
		Target   struct {
			Namespace              string   `json:"namespace"`
			PackageName            string   `json:"package_name"`
			SHA256CertFingerprints []string `json:"sha256_cert_fingerprints"`
		} `json:"target"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stmts); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	if len(stmts) != 1 {
		t.Fatalf("statements = %d, want 1", len(stmts))
	}

	s := stmts[0]
	if len(s.Relation) != 1 || s.Relation[0] != "delegate_permission/common.handle_all_urls" {
		t.Errorf("relation = %v, want [delegate_permission/common.handle_all_urls]", s.Relation)
	}
	if s.Target.Namespace != "android_app" {
		t.Errorf("namespace = %q, want android_app", s.Target.Namespace)
	}
	if s.Target.PackageName != "to.schauer.schautrack" {
		t.Errorf("package_name = %q, want to.schauer.schautrack", s.Target.PackageName)
	}
	if len(s.Target.SHA256CertFingerprints) != 1 || s.Target.SHA256CertFingerprints[0] != fp {
		t.Errorf("sha256_cert_fingerprints = %v, want [%s]", s.Target.SHA256CertFingerprints, fp)
	}
}
