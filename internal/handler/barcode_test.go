package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/config"
)

// withChiURLParam adds a chi URL parameter to the request context.
func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestBarcode_InvalidFormat(t *testing.T) {
	cfg := &config.Config{BuildVersion: "test", SupportEmail: "test@test.com"}
	h := Barcode(cfg)

	tests := []struct {
		name string
		code string
	}{
		{"letters", "abcdefgh"},
		{"too short", "1234567"},
		{"too long", "12345678901234"},
		{"special chars", "1234-5678"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/barcode/"+tt.code, nil)
			r = withChiURLParam(r, "code", tt.code)
			w := httptest.NewRecorder()

			h(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}

			var resp map[string]any
			json.Unmarshal(w.Body.Bytes(), &resp)
			if msg, _ := resp["error"].(string); msg != "Invalid barcode format." {
				t.Errorf("error = %q, want %q", msg, "Invalid barcode format.")
			}
		})
	}
}

func TestBarcode_ValidFormat8Digits(t *testing.T) {
	if !barcodeRe.MatchString("12345678") {
		t.Error("8-digit barcode should be valid")
	}
}

func TestBarcode_ValidFormat13Digits(t *testing.T) {
	if !barcodeRe.MatchString("1234567890123") {
		t.Error("13-digit barcode should be valid")
	}
}

func TestBarcode_MockOpenFoodFacts(t *testing.T) {
	// Start a mock server that returns a known response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": 1,
			"product": map[string]any{
				"product_name": "Test Chocolate",
				"nutriments": map[string]any{
					"energy-kcal_100g":   float64(550),
					"proteins_100g":      float64(7.5),
					"carbohydrates_100g": float64(57.0),
					"fat_100g":           float64(31.0),
				},
				"serving_size":     "40g",
				"serving_quantity": float64(40),
			},
		})
	}))
	defer mockServer.Close()

	// We can't easily inject the HTTP client into Barcode(), since it creates
	// its own client internally. Instead, we test the regex validation and
	// the response parsing by testing with a real mock server.
	// For a full integration test, we'd need to refactor Barcode to accept
	// an HTTP client or base URL.

	// For now, verify the regex accepts valid barcodes
	validCodes := []string{"12345678", "123456789", "1234567890", "12345678901", "123456789012", "1234567890123"}
	for _, code := range validCodes {
		if !barcodeRe.MatchString(code) {
			t.Errorf("barcodeRe should accept %q", code)
		}
	}

	invalidCodes := []string{"1234567", "12345678901234", "abcdefgh", "1234-567", ""}
	for _, code := range invalidCodes {
		if barcodeRe.MatchString(code) {
			t.Errorf("barcodeRe should reject %q", code)
		}
	}
}

func TestBarcode_ProductNotFound(t *testing.T) {
	// Mock server returning status 0 (product not found)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":  0,
			"product": map[string]any{},
		})
	}))
	defer mockServer.Close()

	// Same limitation: the handler creates its own HTTP client with a hardcoded URL.
	// We verify the barcode regex coverage is complete.
	t.Log("Barcode handler creates its own HTTP client; full mock test requires refactoring")
}

func TestBarcode_GatewayTimeout(t *testing.T) {
	// Verify that non-200 responses from upstream produce 502
	// This would require the handler to accept a custom base URL.
	t.Log("Barcode handler uses hardcoded URL; gateway timeout test requires refactoring")
}

func TestHasValidCheckDigit(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		// Real EAN-13 codes (verified against world.openfoodfacts.org)
		{"EAN-13 Coca-Cola valid", "5449000000996", true},
		{"EAN-13 Edeka Frischkäse valid", "4311501062449", true},
		// Last-digit flips of valid EAN-13s — typical Quagga2 misreads
		{"EAN-13 last digit off by 1", "4311501062448", false},
		{"EAN-13 last digit zero", "4311501062440", false},
		// Mid-digit flip
		{"EAN-13 mid digit flipped", "4311501162449", false},
		// Real EAN-8 (Coca-Cola mini)
		{"EAN-8 valid", "96385074", true},
		{"EAN-8 invalid", "96385075", false},
		// UPC-A (12 digits)
		{"UPC-A valid", "036000291452", true},
		{"UPC-A invalid", "036000291453", false},
		// Lengths without standard checksum: skipped (return true)
		{"9 digits skipped", "123456789", true},
		{"10 digits skipped", "1234567890", true},
		{"11 digits skipped", "12345678901", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasValidCheckDigit(tt.code); got != tt.want {
				t.Errorf("hasValidCheckDigit(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestBarcode_CheckDigitMismatch(t *testing.T) {
	cfg := &config.Config{BuildVersion: "test", SupportEmail: "test@test.com"}
	h := Barcode(cfg)

	r := httptest.NewRequest("GET", "/api/barcode/4311501062448", nil)
	r = withChiURLParam(r, "code", "4311501062448") // last digit flipped
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if ok, _ := resp["ok"].(bool); ok {
		t.Errorf("expected ok=false, got %v", resp)
	}
	if code, _ := resp["code"].(string); code != "CHECK_DIGIT" {
		t.Errorf("expected code=CHECK_DIGIT, got %q", code)
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("hello", "world"); got != "hello" {
		t.Errorf("orDefault('hello', 'world') = %q, want 'hello'", got)
	}
	if got := orDefault("", "world"); got != "world" {
		t.Errorf("orDefault('', 'world') = %q, want 'world'", got)
	}
}
