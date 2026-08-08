package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// buildImportRequestWithFields is buildImportRequest plus extra form fields, so
// a test can set dry_run alongside the file.
func buildImportRequestWithFields(t *testing.T, content string, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("import_file", "import.json")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/settings/import", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// A file with one good entry and several unreadable ones, so the dry run has
// something to both accept and report.
const dryRunFixture = `{
  "entries": [
    {"date": "2026-08-05", "amount": 500, "name": "Good"},
    {"date": "not-a-date", "amount": 100},
    {"date": "2026-08-06", "amount": "nonsense"},
    "not an object"
  ],
  "weights": [
    {"date": "2026-08-05", "weight": 82.4},
    {"date": "2026-08-06", "weight": "abc"}
  ]
}`

// TestImportDryRunWritesNothing is the half of #409 that matters most.
//
// The real import DELETEs the account's existing entries before inserting, so
// by the time a user reads "Skipped 7 rows" the data those rows would have
// replaced is already gone and there is nothing left to compare the file
// against. A dry run is the only way to learn that while it is still fixable.
//
// Driven with a NIL Pool: the handler would panic on h.Pool.Begin, so a clean
// 200 is proof the destructive path was never entered. Asserting "no rows
// changed" against a live database would pass just as well if the DELETE ran
// and the INSERT restored the same data — this cannot.
func TestImportDryRunWritesNothing(t *testing.T) {
	h := &EntriesHandler{} // nil Pool: any DB access panics

	for _, flag := range []string{"1", "true", "TRUE", "yes", "on"} {
		rec := httptest.NewRecorder()
		req := buildImportRequestWithFields(t, dryRunFixture, map[string]string{"dry_run": flag})

		h.Import(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("dry_run=%q: status = %d, want 200 (body %s)", flag, rec.Code, rec.Body.String())
		}
		var resp struct {
			OK      bool   `json:"ok"`
			DryRun  bool   `json:"dry_run"`
			Message string `json:"message"`
			Skipped struct {
				Total    int `json:"total"`
				Reported int `json:"reported"`
				Rows     []struct {
					Kind, Date, Reason string
					Index              int
				} `json:"rows"`
			} `json:"skipped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("dry_run=%q: response is not JSON: %v", flag, err)
		}
		if !resp.DryRun {
			t.Errorf("dry_run=%q: response does not say it was a dry run", flag)
		}
		if resp.Skipped.Total != 4 {
			t.Errorf("dry_run=%q: skipped.total = %d, want 4", flag, resp.Skipped.Total)
		}
		if len(resp.Skipped.Rows) != 4 {
			t.Fatalf("dry_run=%q: got %d skipped rows, want 4", flag, len(resp.Skipped.Rows))
		}
	}
}

// TestImportDryRunIsOffByDefault: a missing or falsey flag must NOT take the
// rehearsal path. Getting this backwards would make every real import a no-op
// while reporting success — silent, total data loss of the import itself.
func TestImportDryRunIsOffByDefault(t *testing.T) {
	h := &EntriesHandler{} // nil Pool: reaching the DB panics, which is the signal

	for _, flag := range []string{"", "0", "false", "no", "off", "maybe"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("dry_run=%q did not reach the database — it was treated as a dry run", flag)
				}
			}()
			fields := map[string]string{}
			if flag != "" {
				fields["dry_run"] = flag
			}
			h.Import(httptest.NewRecorder(), buildImportRequestWithFields(t, dryRunFixture, fields))
		}()
	}
}

// TestImportSkippedRowsNameTheRowAndReason pins the diagnostics themselves:
// which row, and why. "7 rows" tells a user something is wrong; it does not
// tell them what to fix.
func TestImportSkippedRowsNameTheRowAndReason(t *testing.T) {
	data := parseImportData(mustParseImportJSON(t, dryRunFixture))

	if got := data.skippedEntries + data.skippedWeights; got != 4 {
		t.Fatalf("skipped total = %d, want 4", got)
	}

	type key struct {
		kind   string
		index  int
		reason string
	}
	got := map[key]string{}
	for _, r := range data.skipped {
		got[key{r.Kind, r.Index, r.Reason}] = r.Date
	}

	want := map[key]string{
		{"entry", 1, "invalid_date"}:    "",           // the date is why it failed: not echoed back
		{"entry", 2, "invalid_amount"}:  "2026-08-06", // date was readable, so it locates the row
		{"entry", 3, "not_an_object"}:   "",
		{"weight", 1, "invalid_weight"}: "2026-08-06",
	}
	for k, wantDate := range want {
		date, ok := got[k]
		if !ok {
			t.Errorf("no skipped row for %+v; got %+v", k, data.skipped)
			continue
		}
		if date != wantDate {
			t.Errorf("%+v: date = %q, want %q", k, date, wantDate)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d skipped rows, want %d: %+v", len(got), len(want), data.skipped)
	}
}

// TestImportSkippedRowsAreCapped: the counters stay truthful past the cap while
// the list stops growing, so a hostile file cannot turn a 10,000-row rejection
// into a 10,000-element response.
func TestImportSkippedRowsAreCapped(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`{"entries":[{"date":"2026-08-05","amount":500}`)
	for i := 0; i < maxReportedSkips*3; i++ {
		b.WriteString(`,{"date":"nope","amount":1}`)
	}
	b.WriteString(`]}`)

	data := parseImportData(mustParseImportJSON(t, b.String()))

	if data.skippedEntries != maxReportedSkips*3 {
		t.Errorf("skippedEntries = %d, want %d — the counter must not be capped",
			data.skippedEntries, maxReportedSkips*3)
	}
	if len(data.skipped) != maxReportedSkips {
		t.Errorf("reported rows = %d, want the cap of %d", len(data.skipped), maxReportedSkips)
	}
}
