package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// mustParseImportJSON decodes a JSON literal the same way the Import handler
// does (json.Unmarshal into map[string]any), so numbers become float64 exactly
// as they would from a real uploaded file.
func mustParseImportJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("test fixture is not valid JSON: %v\n%s", err, s)
	}
	return m
}

// TestParseImportData pins the validation phase that guards the destructive
// import: parseImportData decides which rows survive to be written after the
// user's existing entries are DELETEd. A regression here silently destroys
// user data, so every skip/keep/clamp branch is exercised directly.
func TestParseImportData(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, d importData)
	}{
		{
			name:  "happy path entry and weight",
			input: `{"entries":[{"date":"2025-01-15","amount":420,"name":"Lunch","protein_g":30,"carbs_g":50,"fat_g":10}],"weights":[{"date":"2025-01-15","weight":72.5}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 || len(d.weights) != 1 {
					t.Fatalf("entries=%d weights=%d, want 1/1", len(d.entries), len(d.weights))
				}
				e := d.entries[0]
				if e.date != "2025-01-15" || e.amount != 420 {
					t.Errorf("entry = %+v", e)
				}
				if e.name == nil || *e.name != "Lunch" {
					t.Errorf("name = %v, want Lunch", e.name)
				}
				if p := e.macros["protein"]; p == nil || *p != 30 {
					t.Errorf("protein = %v, want 30", p)
				}
				if d.weights[0].weight != 72.5 {
					t.Errorf("weight = %v, want 72.5", d.weights[0].weight)
				}
			},
		},
		{
			name:  "legacy field names entry_date and entry_name",
			input: `{"entries":[{"entry_date":"2025-02-01","amount":200,"entry_name":"Snack"}],"weights":[{"entry_date":"2025-02-01","weight":70}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 {
					t.Fatalf("entries=%d, want 1", len(d.entries))
				}
				if d.entries[0].date != "2025-02-01" {
					t.Errorf("date = %q", d.entries[0].date)
				}
				if d.entries[0].name == nil || *d.entries[0].name != "Snack" {
					t.Errorf("name = %v, want Snack", d.entries[0].name)
				}
				if len(d.weights) != 1 || d.weights[0].date != "2025-02-01" {
					t.Errorf("weights = %+v", d.weights)
				}
			},
		},
		{
			name:  "amount as string is parsed",
			input: `{"entries":[{"date":"2025-01-15","amount":"300"}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 || d.entries[0].amount != 300 {
					t.Fatalf("entries = %+v, want one amount 300", d.entries)
				}
			},
		},
		{
			name:  "negative amount is kept",
			input: `{"entries":[{"date":"2025-01-15","amount":-250}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 || d.entries[0].amount != -250 {
					t.Fatalf("entries = %+v, want one amount -250", d.entries)
				}
			},
		},
		{
			name:  "invalid date skips the entry",
			input: `{"entries":[{"date":"2025-13-40","amount":100},{"date":"not-a-date","amount":100}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 0 {
					t.Fatalf("entries = %+v, want none (bad dates)", d.entries)
				}
			},
		},
		{
			name:  "zero amount skips the entry",
			input: `{"entries":[{"date":"2025-01-15","amount":0}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 0 {
					t.Fatalf("entries = %+v, want none (amount 0)", d.entries)
				}
			},
		},
		{
			name:  "missing and non-numeric amount skip the entry",
			input: `{"entries":[{"date":"2025-01-15"},{"date":"2025-01-15","amount":"abc"}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 0 {
					t.Fatalf("entries = %+v, want none", d.entries)
				}
			},
		},
		{
			name:  "amount over MaxEntryCalories is rejected not clamped",
			input: `{"entries":[{"date":"2025-01-15","amount":10000}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 0 {
					t.Fatalf("entries = %+v, want none (amount > MaxEntryCalories)", d.entries)
				}
			},
		},
		{
			name:  "out-of-range macro is dropped but entry is kept",
			input: `{"entries":[{"date":"2025-01-15","amount":300,"protein_g":1500,"carbs_g":-5,"fat_g":40}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 {
					t.Fatalf("entries = %+v, want 1", d.entries)
				}
				m := d.entries[0].macros
				if _, ok := m["protein"]; ok {
					t.Errorf("protein should be dropped (>MaxEntryMacro), got %v", m["protein"])
				}
				if _, ok := m["carbs"]; ok {
					t.Errorf("carbs should be dropped (negative), got %v", m["carbs"])
				}
				if f := m["fat"]; f == nil || *f != 40 {
					t.Errorf("fat = %v, want 40 (in range)", m["fat"])
				}
			},
		},
		{
			name:  "non-integer macro is dropped",
			input: `{"entries":[{"date":"2025-01-15","amount":300,"protein_g":30.5}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 {
					t.Fatalf("entries = %+v, want 1", d.entries)
				}
				if _, ok := d.entries[0].macros["protein"]; ok {
					t.Errorf("fractional macro should be dropped, got %v", d.entries[0].macros["protein"])
				}
			},
		},
		{
			name:  "valid created_at is parsed",
			input: `{"entries":[{"date":"2025-01-15","amount":300,"created_at":"2025-01-15T08:30:00Z"}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 || d.entries[0].createdAt == nil {
					t.Fatalf("entries = %+v, want createdAt set", d.entries)
				}
				if got := d.entries[0].createdAt.UTC().Format("2006-01-02T15:04:05Z07:00"); got != "2025-01-15T08:30:00Z" {
					t.Errorf("createdAt = %q", got)
				}
			},
		},
		{
			name:  "malformed created_at is ignored but entry is kept",
			input: `{"entries":[{"date":"2025-01-15","amount":300,"created_at":"2025-01-15"}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 {
					t.Fatalf("entries = %+v, want 1", d.entries)
				}
				if d.entries[0].createdAt != nil {
					t.Errorf("createdAt = %v, want nil (malformed timestamp)", d.entries[0].createdAt)
				}
			},
		},
		{
			name:  "non-object entry element is skipped",
			input: `{"entries":["garbage",42,{"date":"2025-01-15","amount":300}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.entries) != 1 || d.entries[0].amount != 300 {
					t.Fatalf("entries = %+v, want one amount 300", d.entries)
				}
			},
		},
		{
			name:  "zero and negative weights are skipped",
			input: `{"weights":[{"date":"2025-01-15","weight":0},{"date":"2025-01-15","weight":-5},{"date":"2025-01-15","weight":80}]}`,
			check: func(t *testing.T, d importData) {
				if len(d.weights) != 1 || d.weights[0].weight != 80 {
					t.Fatalf("weights = %+v, want one weight 80", d.weights)
				}
			},
		},
		{
			name:  "goal from user.macro_goals.calories wins over daily_goal",
			input: `{"daily_goal":1800,"user":{"macro_goals":{"calories":2200},"daily_goal":1700}}`,
			check: func(t *testing.T, d importData) {
				if d.goalCandidate == nil || *d.goalCandidate != 2200 {
					t.Errorf("goalCandidate = %v, want 2200", d.goalCandidate)
				}
				if !d.hasUserSettings {
					t.Errorf("hasUserSettings = false, want true")
				}
			},
		},
		{
			name:  "goal from top-level daily_goal without user object",
			input: `{"daily_goal":1900}`,
			check: func(t *testing.T, d importData) {
				if d.goalCandidate == nil || *d.goalCandidate != 1900 {
					t.Errorf("goalCandidate = %v, want 1900", d.goalCandidate)
				}
				// No "user" object present, so this is not counted as user
				// settings — a file with only a top-level daily_goal and no
				// entries is empty and must be rejected with 400.
				if d.hasUserSettings {
					t.Errorf("hasUserSettings = true, want false (no user object)")
				}
				if !d.isEmpty() {
					t.Errorf("isEmpty = false, want true")
				}
			},
		},
		{
			name:  "goal from user.daily_goal fallback",
			input: `{"user":{"daily_goal":1600}}`,
			check: func(t *testing.T, d importData) {
				if d.goalCandidate == nil || *d.goalCandidate != 1600 {
					t.Errorf("goalCandidate = %v, want 1600", d.goalCandidate)
				}
				if !d.hasUserSettings {
					t.Errorf("hasUserSettings = false, want true")
				}
			},
		},
		{
			name:  "weight_unit alone counts as user settings",
			input: `{"user":{"weight_unit":"kg"}}`,
			check: func(t *testing.T, d importData) {
				if !d.hasUserSettings {
					t.Errorf("hasUserSettings = false, want true")
				}
				if d.isEmpty() {
					t.Errorf("isEmpty = true, want false")
				}
			},
		},
		{
			name:  "empty user object is not user settings",
			input: `{"user":{}}`,
			check: func(t *testing.T, d importData) {
				if d.hasUserSettings {
					t.Errorf("hasUserSettings = true, want false")
				}
				if !d.isEmpty() {
					t.Errorf("isEmpty = false, want true")
				}
			},
		},
		{
			name:  "all-invalid entries produce an empty import",
			input: `{"entries":[{"date":"bad","amount":"x"},{"amount":100},{"date":"2025-01-15","amount":0}]}`,
			check: func(t *testing.T, d importData) {
				if !d.isEmpty() {
					t.Errorf("isEmpty = false, want true for all-invalid input: %+v", d)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := parseImportData(mustParseImportJSON(t, tt.input))
			tt.check(t, d)
		})
	}
}

// TestParseImportData_NameTruncatedOnMultibyte verifies a long emoji name is
// cut to <=120 bytes without splitting a multi-byte rune (invalid UTF-8 would
// make Postgres reject the whole INSERT and abort the import).
func TestParseImportData_NameTruncatedOnMultibyte(t *testing.T) {
	longName := strings.Repeat("🍎", 50) // 50 * 4 = 200 bytes
	input := map[string]any{
		"entries": []any{
			map[string]any{"date": "2025-01-15", "amount": float64(300), "name": longName},
		},
	}
	d := parseImportData(input)
	if len(d.entries) != 1 || d.entries[0].name == nil {
		t.Fatalf("entries = %+v, want one named entry", d.entries)
	}
	name := *d.entries[0].name
	if len(name) > 120 {
		t.Errorf("name len = %d bytes, want <= 120", len(name))
	}
	if !utf8.ValidString(name) {
		t.Errorf("truncated name is not valid UTF-8: %q", name)
	}
	if !strings.HasPrefix(longName, name) {
		t.Errorf("truncated name is not a prefix of the original")
	}
}

// TestParseImportData_CapsAtTenThousand verifies each collection is capped so a
// hostile file cannot force an unbounded batch after wiping existing rows.
func TestParseImportData_CapsAtTenThousand(t *testing.T) {
	entries := make([]any, 10001)
	weights := make([]any, 10001)
	for i := range entries {
		entries[i] = map[string]any{"date": "2025-01-15", "amount": float64(100)}
		weights[i] = map[string]any{"date": "2025-01-15", "weight": float64(80)}
	}
	d := parseImportData(map[string]any{"entries": entries, "weights": weights})
	if len(d.entries) != 10000 {
		t.Errorf("entries = %d, want 10000", len(d.entries))
	}
	if len(d.weights) != 10000 {
		t.Errorf("weights = %d, want 10000", len(d.weights))
	}
}

// buildImportRequest builds a POST /settings/import multipart request. When
// fieldName is empty the file part is omitted entirely (to exercise the
// "no file uploaded" path).
func buildImportRequest(t *testing.T, fieldName, content string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if fieldName != "" {
		fw, err := mw.CreateFormFile(fieldName, "import.json")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatalf("write file part: %v", err)
		}
	} else {
		// Include an unrelated field so the multipart body is well-formed.
		if err := mw.WriteField("other", "x"); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/settings/import", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// TestImport_RejectsBadInputBeforeAnyDBAccess drives the handler with a nil
// Pool and no authenticated user. Each of these inputs must be rejected before
// Import reaches h.Pool.Begin / the DELETE — a nil Pool would panic on any DB
// call, so a clean 400 proves the destructive path is never entered and no
// existing data is deleted.
func TestImport_RejectsBadInputBeforeAnyDBAccess(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		content   string
		wantMsg   string
	}{
		{"no file uploaded", "", "", "No file uploaded."},
		{"malformed json", "import_file", "{not valid json", "Invalid JSON file."},
		{"all-invalid entries deletes nothing", "import_file",
			`{"entries":[{"date":"bad","amount":"x"},{"date":"2025-01-15","amount":0}]}`,
			"No valid entries found in import file."},
		{"empty object deletes nothing", "import_file", `{}`,
			"No valid entries found in import file."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &EntriesHandler{} // nil Pool: any DB access would panic
			r := buildImportRequest(t, tt.fieldName, tt.content)
			w := httptest.NewRecorder()

			// If the handler reached the destructive DELETE it would panic on
			// the nil Pool; recover so the failure is a readable assertion.
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Import panicked (reached DB access on invalid input): %v", rec)
				}
			}()
			h.Import(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
			}
			if ok, _ := resp["ok"].(bool); ok {
				t.Errorf("ok = true, want false")
			}
			if msg, _ := resp["error"].(string); msg != tt.wantMsg {
				t.Errorf("error = %q, want %q", msg, tt.wantMsg)
			}
		})
	}
}
