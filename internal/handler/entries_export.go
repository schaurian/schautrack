package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

// execBatch sends a pgx batch on the transaction and returns the first error
// encountered, draining the batch results before returning so the connection
// is safe to use (e.g. for rollback) afterwards.
func execBatch(ctx context.Context, tx pgx.Tx, batch *pgx.Batch) error {
	br := tx.SendBatch(ctx, batch)
	var firstErr error
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			firstErr = err
			break
		}
	}
	if err := br.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Export handles POST /settings/export.
// Returns the user's full data set as a JSON download. Authorization is via
// the step-up middleware on the route — the caller has already proven
// identity. POST (not GET) so CSRF protection applies and the client can
// retry through the step-up modal interceptor.
func (h *EntriesHandler) Export(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)

	entries, err := h.Pool.Query(r.Context(),
		"SELECT entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000",
		user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Export failed")
		return
	}
	defer entries.Close()

	weights, err := h.Pool.Query(r.Context(),
		"SELECT entry_date, weight, body_fat FROM weight_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000",
		user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Export failed")
		return
	}
	defer weights.Close()

	filename := fmt.Sprintf("schautrack-export-%s.json", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	tz := "UTC"
	if user.Timezone != nil {
		tz = *user.Timezone
	}

	var macrosEnabled, macroGoalsRaw any
	if err := json.Unmarshal(user.MacrosEnabled, &macrosEnabled); err != nil {
		slog.Error("failed to unmarshal macros_enabled in export", "error", err)
	}
	if err := json.Unmarshal(user.MacroGoals, &macroGoalsRaw); err != nil {
		slog.Error("failed to unmarshal macro_goals in export", "error", err)
	}
	if macrosEnabled == nil {
		macrosEnabled = map[string]any{}
	}
	if macroGoalsRaw == nil {
		macroGoalsRaw = map[string]any{}
	}

	userExport := map[string]any{
		"email": user.Email, "daily_goal": service.GetCalorieGoal(mu),
		"macros_enabled": macrosEnabled, "macro_goals": macroGoalsRaw,
		"weight_unit": user.WeightUnit, "timezone": tz,
	}

	fmt.Fprint(w, "{\n")
	fmt.Fprintf(w, `"exported_at":%q,`+"\n", time.Now().UTC().Format(time.RFC3339))
	userJSON, _ := json.Marshal(userExport)
	fmt.Fprintf(w, `"user":%s,`+"\n", userJSON)

	// Weights
	fmt.Fprint(w, `"weights":[`)
	first := true
	for weights.Next() {
		var date string
		var weight float64
		var bodyFat *float64
		if err := weights.Scan(&date, &weight, &bodyFat); err != nil {
			slog.Error("failed to scan weight row in export", "error", err)
			continue
		}
		if !first {
			fmt.Fprint(w, ",")
		}
		row := map[string]any{"date": date, "weight": weight}
		// Omitted rather than exported as null, so an export from before body
		// fat existed and one from a user who never measures it look identical.
		if bodyFat != nil {
			row["body_fat"] = *bodyFat
		}
		wj, _ := json.Marshal(row)
		w.Write(wj)
		first = false
	}
	if err := weights.Err(); err != nil {
		// The response is already partially written, so we cannot send an
		// error status. Abort without closing the JSON structure: a
		// deliberately truncated, invalid file cannot be mistaken for a
		// complete backup.
		slog.Error("export aborted: weight row iteration failed", "error", err)
		return
	}
	fmt.Fprint(w, "],\n")

	// Entries
	fmt.Fprint(w, `"entries":[`)
	first = true
	for entries.Next() {
		var date string
		var amount int
		var name *string
		var createdAt *time.Time
		var proteinG, carbsG, fatG, fiberG, sugarG *int
		if err := entries.Scan(&date, &amount, &name, &createdAt, &proteinG, &carbsG, &fatG, &fiberG, &sugarG); err != nil {
			slog.Error("failed to scan entry row in export", "error", err)
			continue
		}
		if !first {
			fmt.Fprint(w, ",")
		}
		entry := map[string]any{"date": date, "amount": amount, "name": name}
		if createdAt != nil {
			entry["created_at"] = createdAt.UTC().Format(time.RFC3339)
		}
		if proteinG != nil {
			entry["protein_g"] = *proteinG
		}
		if carbsG != nil {
			entry["carbs_g"] = *carbsG
		}
		if fatG != nil {
			entry["fat_g"] = *fatG
		}
		if fiberG != nil {
			entry["fiber_g"] = *fiberG
		}
		if sugarG != nil {
			entry["sugar_g"] = *sugarG
		}
		ej, _ := json.Marshal(entry)
		w.Write(ej)
		first = false
	}
	if err := entries.Err(); err != nil {
		// See the weights.Err() comment above: leave the JSON truncated so
		// a partial export is detectably invalid.
		slog.Error("export aborted: entry row iteration failed", "error", err)
		return
	}
	fmt.Fprint(w, "]\n}")
}

// importEntry is a single calorie entry that survived import validation and is
// ready to be inserted into calorie_entries.
type importEntry struct {
	date      string
	amount    int
	name      *string
	createdAt *time.Time
	macros    map[string]*int
}

// importWeight is a single weight entry that survived import validation.
type importWeight struct {
	date    string
	weight  float64
	bodyFat *float64
}

// importData is the fully validated payload extracted from an import file:
// only rows/settings safe to write survive here. It is produced by
// parseImportData with no database, request, or user access so the
// destructive-import parse phase can be unit tested in isolation.
type importData struct {
	entries         []importEntry
	weights         []importWeight
	goalCandidate   *float64
	hasUserSettings bool
	// skippedEntries and skippedWeights count the rows that were present in
	// the file but did not survive validation, including the ones dropped by
	// the 10,000-row cap. Import reports the total so a partial import stops
	// being indistinguishable from a complete one — a row with an amount the
	// server could not parse used to just vanish, and the response still said
	// the import succeeded (#351).
	skippedEntries int
	skippedWeights int

	// skipped names the dropped rows: which one, and why. The counts above
	// say a partial import happened; this says what to fix (#409). With a
	// 500-row export and seven bad amounts, "7 rows" is enough to know
	// something is wrong and not enough to do anything about it — and the
	// import DELETEs the user's existing entries first, so there is no second
	// chance to diff against the original.
	//
	// Capped at maxReportedSkips so a hostile file cannot turn a 10,000-row
	// rejection into a 10,000-element response; skippedEntries/skippedWeights
	// remain the true totals.
	skipped []skippedRow
}

// maxReportedSkips bounds the per-row detail. Fifty is well past the point
// where a human is reading individual rows and still small enough that the
// response stays a response.
const maxReportedSkips = 50

// skippedRow is one dropped import row. Reason is a stable code rather than
// prose so a client can group or translate it; the wire shape is documented on
// the ImportResult schema.
type skippedRow struct {
	// Kind is "entry" or "weight" — the two arrays are indexed separately, so
	// an index alone would be ambiguous.
	Kind string `json:"kind"`
	// Index is the row's position in its array in the uploaded file, so the
	// user can go straight to it.
	Index int `json:"index"`
	// Date is the row's date when it had a readable one. Absent when the date
	// itself is why the row was dropped.
	Date string `json:"date,omitempty"`
	// Reason is one of: not_an_object, invalid_date, invalid_amount,
	// invalid_weight, row_limit.
	Reason string `json:"reason"`
}

// record appends a skip, up to the cap. Callers still bump the counters, so
// the totals stay accurate past it.
func (d *importData) record(kind string, index int, date, reason string) {
	if len(d.skipped) >= maxReportedSkips {
		return
	}
	d.skipped = append(d.skipped, skippedRow{Kind: kind, Index: index, Date: date, Reason: reason})
}

// isEmpty reports whether the import carries nothing worth writing. Import
// returns 400 — and, critically, performs no destructive DELETE — when this is
// true, so a garbage or all-invalid file can never wipe the user's data.
func (d importData) isEmpty() bool {
	return len(d.entries) == 0 && len(d.weights) == 0 && !d.hasUserSettings
}

// parseImportData validates and extracts the importable payload from an
// already-JSON-decoded import file. It is a pure function (no DB, no request,
// no user) so the validation that guards the destructive import — the loop
// that rejects bad dates, zero/oversized amounts, malformed timestamps and
// out-of-range macros — can be table-tested directly. Invalid rows are
// skipped rather than failing the import, but they are counted into
// skippedEntries/skippedWeights so Import can say so; entries and weights are
// each capped at 10,000 rows, and the rows past the cap count as skipped too.
func parseImportData(parsed map[string]any) importData {
	// Extract calorie goal from various formats
	var goalCandidate *float64
	if userObj, ok := parsed["user"].(map[string]any); ok {
		if mg, ok := userObj["macro_goals"].(map[string]any); ok {
			if v, ok := mg["calories"].(float64); ok {
				goalCandidate = &v
			}
		}
	}
	if goalCandidate == nil {
		if v, ok := parsed["daily_goal"].(float64); ok {
			goalCandidate = &v
		}
	}
	if goalCandidate == nil {
		if userObj, ok := parsed["user"].(map[string]any); ok {
			if v, ok := userObj["daily_goal"].(float64); ok {
				goalCandidate = &v
			}
		}
	}

	// Parse entries
	//
	// rec collects the per-row detail as we go; the counters stay the source of
	// truth for the totals, because rec stops appending at maxReportedSkips.
	var rec importData
	var toInsert []importEntry
	var skippedEntries int
	if entries, ok := parsed["entries"].([]any); ok {
		for i, e := range entries {
			if len(toInsert) >= 10000 {
				skippedEntries += len(entries) - i
				rec.record("entry", i, "", "row_limit")
				break
			}
			entry, ok := e.(map[string]any)
			if !ok {
				skippedEntries++
				rec.record("entry", i, "", "not_an_object")
				continue
			}
			dateStr := ""
			if v, ok := entry["date"].(string); ok {
				dateStr = v
			} else if v, ok := entry["entry_date"].(string); ok {
				dateStr = v
			}
			if !isValidDate(dateStr) {
				// No date reported: the date is why this row was dropped, and
				// echoing an unparseable one back would suggest it was read.
				skippedEntries++
				rec.record("entry", i, "", "invalid_date")
				continue
			}
			amountResult := service.ParseAmount(fmt.Sprintf("%v", entry["amount"]), MaxEntryCalories)
			if !amountResult.Ok || amountResult.Value == 0 {
				skippedEntries++
				rec.record("entry", i, dateStr, "invalid_amount")
				continue
			}
			var name *string
			if n, ok := entry["name"].(string); ok && n != "" {
				s := truncateUTF8(n, 120)
				name = &s
			} else if n, ok := entry["entry_name"].(string); ok && n != "" {
				s := truncateUTF8(n, 120)
				name = &s
			}
			var createdAt *time.Time
			if v, ok := entry["created_at"].(string); ok && v != "" {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					createdAt = &t
				}
			}
			macros := map[string]*int{}
			for _, key := range service.MacroKeys {
				field := key + "_g"
				if v, ok := entry[field]; ok {
					vStr := fmt.Sprintf("%v", v)
					if n, err := strconv.Atoi(vStr); err == nil && n >= 0 && n <= MaxEntryMacro {
						macros[key] = &n
					}
				}
			}
			toInsert = append(toInsert, importEntry{date: dateStr, amount: amountResult.Value, name: name, createdAt: createdAt, macros: macros})
		}
	}

	// Parse weight entries
	var weightToInsert []importWeight
	var skippedWeights int
	if weights, ok := parsed["weights"].([]any); ok {
		for i, w := range weights {
			if len(weightToInsert) >= 10000 {
				skippedWeights += len(weights) - i
				rec.record("weight", i, "", "row_limit")
				break
			}
			wEntry, ok := w.(map[string]any)
			if !ok {
				skippedWeights++
				rec.record("weight", i, "", "not_an_object")
				continue
			}
			dateStr := ""
			if v, ok := wEntry["date"].(string); ok {
				dateStr = v
			} else if v, ok := wEntry["entry_date"].(string); ok {
				dateStr = v
			}
			if !isValidDate(dateStr) {
				skippedWeights++
				rec.record("weight", i, "", "invalid_date")
				continue
			}
			wr := service.ParseWeight(fmt.Sprintf("%v", wEntry["weight"]))
			if !wr.Ok {
				skippedWeights++
				rec.record("weight", i, dateStr, "invalid_weight")
				continue
			}
			// An unparseable body fat drops just that field — the weight is
			// still worth restoring, matching how a bad macro drops a macro
			// rather than the whole entry.
			var bodyFat *float64
			if raw, exists := wEntry["body_fat"]; exists && raw != nil {
				if pct, ok := service.ParseBodyFat(fmt.Sprintf("%v", raw)); ok {
					bodyFat = &pct
				}
			}
			weightToInsert = append(weightToInsert, importWeight{date: dateStr, weight: wr.Value, bodyFat: bodyFat})
		}
	}

	// Check user settings
	hasUserSettings := false
	if userObj, ok := parsed["user"].(map[string]any); ok {
		if userObj["macros_enabled"] != nil || userObj["macro_goals"] != nil || goalCandidate != nil || userObj["weight_unit"] != nil || userObj["timezone"] != nil {
			hasUserSettings = true
		}
	}

	return importData{
		entries:         toInsert,
		weights:         weightToInsert,
		goalCandidate:   goalCandidate,
		hasUserSettings: hasUserSettings,
		skippedEntries:  skippedEntries,
		skippedWeights:  skippedWeights,
		skipped:         rec.skipped,
	}
}

// importMessage renders the success text for a completed import.
//
// The skipped count is the point of it. parseImportData drops any row it
// cannot read — an unparseable amount, a bad date, a row past the 10,000 cap —
// and the response used to report an unqualified success, so a file whose
// amounts the server could not parse imported as "Imported 3 entries." with no
// hint that seven more rows were thrown away (#351). Saying how many were
// dropped costs nothing and turns silent data loss into something the user can
// act on.
//
// This stays inside the existing `message` string rather than adding a field
// to the response: Account.tsx renders `message` verbatim, so it reaches the
// user with no client, OpenAPI or i18n change. Per-row diagnostics (which rows,
// and why) would need a real response-shape change and are filed as #409.
// importParts renders the "N entries and M weight records" fragment. Shared so
// the dry run and the real import cannot describe the same file differently —
// the whole point of a rehearsal is that it predicts the performance.
//
// hasUserSettings is not included here: the dry run reports it identically via
// its own caller, and threading a fourth boolean through would obscure that
// these two lists must stay in step.
func importParts(entries, weights int) []string {
	var parts []string
	if entries > 0 {
		parts = append(parts, fmt.Sprintf("%d entries", entries))
	}
	if weights > 0 {
		parts = append(parts, fmt.Sprintf("%d weight records", weights))
	}
	return parts
}

// isTruthyFormValue reads a multipart flag. Accepts the spellings an HTML form
// and a scripted client each produce, rather than only Go's strconv set.
func isTruthyFormValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// importSkippedPayload renders the per-row diagnostics.
//
// total is reported separately from the list because the list is capped: a
// file with 10,000 unreadable rows reports all 10,000 in `total` and the first
// maxReportedSkips in `rows`, so the number is never quietly wrong and the
// response never grows with a hostile file.
func importSkippedPayload(d importData) map[string]any {
	rows := d.skipped
	if rows == nil {
		rows = []skippedRow{}
	}
	return map[string]any{
		"total":    d.skippedEntries + d.skippedWeights,
		"reported": len(rows),
		"rows":     rows,
	}
}

// dryRunParts mirrors what the real import reports, including user settings, so
// the rehearsal and the performance describe the same file identically.
func dryRunParts(entries []importEntry, weights []importWeight, hasUserSettings bool) []string {
	parts := importParts(len(entries), len(weights))
	if hasUserSettings {
		parts = append(parts, "user settings")
	}
	return parts
}

func importMessage(parts []string, skipped int) string {
	msg := fmt.Sprintf("Imported %s.", strings.Join(parts, " and "))
	if skipped > 0 {
		unit := "rows"
		if skipped == 1 {
			unit = "row"
		}
		msg += fmt.Sprintf(" Skipped %d %s that could not be read.", skipped, unit)
	}
	return msg
}

// Import handles POST /settings/import
func (h *EntriesHandler) Import(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "No file uploaded.")
		return
	}
	file, _, err := r.FormFile("import_file")
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "No file uploaded.")
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, 10<<20))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Could not read file.")
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid JSON file.")
		return
	}

	// Validate and extract the importable payload before touching the
	// database. The emptiness guard below must run before any DELETE so a
	// garbage file can never wipe the user's existing data.
	data := parseImportData(parsed)
	toInsert := data.entries
	weightToInsert := data.weights
	goalCandidate := data.goalCandidate
	hasUserSettings := data.hasUserSettings

	if data.isEmpty() {
		ErrorJSON(w, http.StatusBadRequest, "No valid entries found in import file.")
		return
	}

	// Dry run: report exactly what a real import would do, and write nothing
	// (#409).
	//
	// This matters more than the per-row detail below it. The import DELETEs
	// the account's existing entries before inserting, so by the time a user
	// reads "Skipped 7 rows" the data those rows would have replaced is
	// already gone — there is nothing left to diff the file against. A dry run
	// is the only way to find that out while it is still fixable.
	//
	// Deliberately placed after isEmpty: a file with nothing importable is a
	// 400 whether or not this is a rehearsal, and answering "nothing would be
	// written" with 200 would read as success.
	if isTruthyFormValue(r.FormValue("dry_run")) {
		JSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"dry_run": true,
			"message": importMessage(dryRunParts(toInsert, weightToInsert, hasUserSettings),
				data.skippedEntries+data.skippedWeights) + " Nothing was written.",
			"skipped": importSkippedPayload(data),
		})
		return
	}

	user := middleware.GetCurrentUser(r)

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
		return
	}
	defer tx.Rollback(r.Context())

	if len(toInsert) > 0 {
		if _, err := tx.Exec(r.Context(), "DELETE FROM calorie_entries WHERE user_id = $1", user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}
	if len(weightToInsert) > 0 {
		if _, err := tx.Exec(r.Context(), "DELETE FROM weight_entries WHERE user_id = $1", user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	// Import user settings
	if userObj, ok := parsed["user"].(map[string]any); ok {
		importedMacrosEnabled, _ := userObj["macros_enabled"].(map[string]any)
		importedMacroGoals, _ := userObj["macro_goals"].(map[string]any)
		if importedMacrosEnabled != nil || importedMacroGoals != nil || goalCandidate != nil {
			meJSON, _ := json.Marshal(importedMacrosEnabled)
			mgJSON, _ := json.Marshal(importedMacroGoals)
			if _, err := tx.Exec(r.Context(), "UPDATE users SET macros_enabled = $1, macro_goals = $2 WHERE id = $3", meJSON, mgJSON, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
		if wu, ok := userObj["weight_unit"].(string); ok && (wu == "kg" || wu == "lb") {
			if _, err := tx.Exec(r.Context(), "UPDATE users SET weight_unit = $1 WHERE id = $2", wu, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
		if tz, ok := userObj["timezone"].(string); ok && len(tz) <= 50 {
			if _, err := tx.Exec(r.Context(), "UPDATE users SET timezone = $1, timezone_manual = TRUE WHERE id = $2", tz, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
	}

	// Insert entries. Up to 10,000 rows may be imported, so send the
	// INSERTs as a pipelined pgx batch on the transaction instead of one
	// round-trip per row. Per-row values and error semantics are unchanged:
	// any failed statement aborts the import and rolls back the tx.
	if len(toInsert) > 0 {
		batch := &pgx.Batch{}
		for _, entry := range toInsert {
			cols := "user_id, entry_date, amount, entry_name"
			vals := "$1, $2, $3, $4"
			args := []any{user.ID, entry.date, entry.amount, entry.name}
			idx := 5
			if entry.createdAt != nil {
				cols += ", created_at"
				vals += fmt.Sprintf(", $%d", idx)
				args = append(args, *entry.createdAt)
				idx++
			}
			for _, key := range service.MacroKeys {
				if v, ok := entry.macros[key]; ok {
					cols += ", " + key + "_g"
					vals += fmt.Sprintf(", $%d", idx)
					args = append(args, v)
					idx++
				}
			}
			batch.Queue(fmt.Sprintf("INSERT INTO calorie_entries (%s) VALUES (%s)", cols, vals), args...)
		}
		if err := execBatch(r.Context(), tx, batch); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	// Weight rows are batched the same way. This inlines the upsert
	// statement from service.UpsertWeightEntry (minus the unused RETURNING
	// clause) because a batch queues raw SQL.
	if len(weightToInsert) > 0 {
		batch := &pgx.Batch{}
		importedBodyFat := false
		for _, we := range weightToInsert {
			batch.Queue(`
				INSERT INTO weight_entries (user_id, entry_date, weight, body_fat)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (user_id, entry_date)
					DO UPDATE SET weight = EXCLUDED.weight, body_fat = EXCLUDED.body_fat, updated_at = NOW()`,
				user.ID, we.date, we.weight, we.bodyFat)
			importedBodyFat = importedBodyFat || we.bodyFat != nil
		}
		// Turn the opt-in on when the file actually carries body fat, so the
		// restored readings are visible and editable straight away instead of
		// sitting in the database behind a preference the user never set.
		if importedBodyFat {
			batch.Queue("UPDATE users SET body_fat_enabled = TRUE WHERE id = $1", user.ID)
		}
		if err := execBatch(r.Context(), tx, batch); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Import failed — the file may contain invalid data.")
		return
	}

	parts := importParts(len(toInsert), len(weightToInsert))
	if hasUserSettings {
		parts = append(parts, "user settings")
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"dry_run": false,
		"message": importMessage(parts, data.skippedEntries+data.skippedWeights),
		"skipped": importSkippedPayload(data),
	})
}
