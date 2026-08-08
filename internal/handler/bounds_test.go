package handler

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"schautrack/internal/service"
)

// Every user-supplied numeric or enum field in this app is bounded twice: once
// in Go, so the caller gets a 400, and once as a Postgres CHECK (or a column
// type), so the data cannot be corrupted. The two are kept in sync entirely by
// hand.
//
//   - Go looser than the DB  -> the value passes validation and then blows up on
//     INSERT: a 500 where the caller should have got a 400.
//   - Go tighter than the DB -> a legitimate value is refused with no
//     explanation, and nothing anywhere says why.
//
// The invariant was documented in three separate comments (plan.go's
// validateRateKgPerWeek, service/utils.go's MaxBodyFatPct, migrations.go's
// ensureBodyFatSchema) and enforced by nothing. This file is the enforcement,
// in the form the issue asks for:
//
//  1. this file — a pure-Go table pinning each Go limit to the literal written
//     in internal/database/migrations.go. No database, so it runs in CI today.
//  2. bounds_db_test.go — the same pairs driven behaviourally against a real
//     Postgres, which needs no hand-maintained literals at all.
//
// Both halves are needed. This one fails the moment someone edits one side of a
// pair; the other one fails even when someone edits both sides consistently but
// wrongly.

// migrationsSourcePath is read rather than imported: the CHECK expressions live
// inside Go string literals in that file, so there is nothing to import.
const migrationsSourcePath = "../database/migrations.go"

var whitespaceRun = regexp.MustCompile(`\s+`)

// migrationSource returns migrations.go with every run of whitespace collapsed
// to a single space, so the anchors below can be written the way the SQL reads
// rather than the way it happens to be indented inside a Go raw string.
func migrationSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(migrationsSourcePath)
	if err != nil {
		t.Fatalf("reading %s failed: %v", migrationsSourcePath, err)
	}
	return strings.TrimSpace(whitespaceRun.ReplaceAllString(string(b), " "))
}

// sqlSite says where in migrations.go a constraint is written, which decides
// how its text is extracted.
type sqlSite int

const (
	// inlineCheck: `... CHECK (<expr>)` written directly in the DDL.
	inlineCheck sqlSite = iota
	// goTableCheck: a {"<constraint name>", "<expr>"} row in a Go slice that a
	// loop turns into ALTER TABLE ... ADD CONSTRAINT statements.
	goTableCheck
	// columnType: no CHECK at all — the limit is the declared column type, e.g.
	// NUMERIC(6,2) holding at most 9999.99.
	columnType
)

// constraintText returns the SQL that anchor identifies: the CHECK expression
// for a constraint, or the column declaration itself for columnType. anchor
// must occur exactly once, which is what makes a renamed constraint fail here
// instead of silently matching nothing.
func constraintText(t *testing.T, src string, site sqlSite, anchor string) string {
	t.Helper()
	if n := strings.Count(src, anchor); n != 1 {
		t.Fatalf("anchor %q occurs %d times in %s, want exactly 1 — this table is out of date with the schema",
			anchor, n, migrationsSourcePath)
	}
	switch site {
	case columnType:
		return anchor
	case goTableCheck:
		re := regexp.MustCompile(`\{"` + regexp.QuoteMeta(anchor) + `", "([^"]*)"\}`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("constraint %q is not a {\"name\", \"expr\"} row in %s any more", anchor, migrationsSourcePath)
		}
		return m[1]
	default:
		rest := src[strings.Index(src, anchor):]
		i := strings.Index(rest, "CHECK (")
		if i < 0 {
			t.Fatalf("no CHECK ( follows anchor %q in %s", anchor, migrationsSourcePath)
		}
		return balancedExpr(t, rest[i+len("CHECK ("):])
	}
}

// balancedExpr returns everything up to the ")" that closes an already-opened
// "(", so a CHECK whose body contains nested parens is not truncated.
func balancedExpr(t *testing.T, s string) string {
	t.Helper()
	depth := 1
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	t.Fatalf("unbalanced CHECK ( ... ) in %s", migrationsSourcePath)
	return ""
}

type limitKind int

const (
	lowerLimit limitKind = iota
	upperLimit
)

func (k limitKind) String() string {
	if k == lowerLimit {
		return "lower"
	}
	return "upper"
}

// bound pins ONE end of ONE range: the extreme value the Go validator accepts
// against the extreme value Postgres accepts for the column that value is
// written to.
//
// goLimit/sqlLimit record the NUMBER at each end; goExclusive records whether
// the Go comparison includes it. probe is the real validator, driven at the
// limit and one grid step past it, so this table pins the VALIDATOR and not
// merely the constant it is supposed to be using.
type bound struct {
	what        string    // the Go side, in prose
	kind        limitKind //
	goLimit     float64   // the boundary value on the Go side
	goExclusive bool      // true when the validator rejects goLimit itself
	sqlLimit    float64   // the most extreme value Postgres accepts
	exact       bool      // the two are meant to be literally the same number
	widerWhy    string    // for !exact rows: why the DB is deliberately wider
	probe       func(float64) bool
	probeStep   float64 // granularity of the value grid: 1, 0.1 or 0.01
	site        sqlSite
	anchor      string // unique substring of migrations.go
	literal     string // text that must appear in the anchored SQL
}

// gridStep moves v by dir steps along the 1/step grid, doing the arithmetic in
// integer units so 1500 + 0.01 is the double nearest 1500.01 rather than
// 1500.0100000000000477 (which would then be rejected by ParseWeight's length
// cap instead of by its range check, and pass for the wrong reason).
func gridStep(v, step float64, dir int) float64 {
	scale := math.Round(1 / step)
	return (math.Round(v*scale) + float64(dir)) / scale
}

// numericDecl matches a NUMERIC(p,s) column declaration, whose maximum value is
// 10^(p-s) - 10^-s. That arithmetic is the whole reason validateRateKgPerWeek
// has an upper bound, so the test derives it rather than trusting the table.
var numericDecl = regexp.MustCompile(`NUMERIC\((\d+), ?(\d+)\)`)

func numericColumnMax(t *testing.T, decl string) float64 {
	t.Helper()
	m := numericDecl.FindStringSubmatch(decl)
	if m == nil {
		t.Fatalf("column declaration %q is not a NUMERIC(p,s)", decl)
	}
	p, _ := strconv.Atoi(m[1])
	s, _ := strconv.Atoi(m[2])
	return math.Pow10(p-s) - math.Pow10(-s)
}

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func nearly(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// The probes below are the real validators, adapted to a float64 signature.
var (
	probeEntryCalories = func(v float64) bool { return entryCaloriesInRange(int(math.Round(v))) }
	probeSavedAmount   = func(v float64) bool {
		return service.ParseAmount(fmtNum(v), MaxEntryCalories).Ok
	}
	probeMacro = func(v float64) bool {
		n := int(math.Round(v))
		_, ok := multiplyMacro(&n, 1)
		return ok
	}
	probeWeight  = func(v float64) bool { return service.ParseWeight(fmtNum(v)).Ok }
	probeBodyFat = func(v float64) bool { _, ok := service.ParseBodyFat(fmtNum(v)); return ok }
	probeHeight  = func(v float64) bool { return validateHeightCm(&v) }
	probeBirth   = func(v float64) bool {
		y := int(math.Round(v))
		return validateBirthYear(&y, time.Now().Year())
	}
	probeDateYear = func(v float64) bool {
		return isValidDate(fmt.Sprintf("%04d-06-15", int(math.Round(v))))
	}
	probeRate         = func(v float64) bool { return validateRateKgPerWeek("rate", &v) }
	probeTargetWeight = validateTargetWeight
)

// goBounds is the hand-maintained half of the drift guard. Editing either side
// of a pair without editing the other fails this test.
func goBounds(t *testing.T) []bound {
	t.Helper()
	return []bound{
		// ---- calorie_entries.amount -------------------------------------
		{
			what: "handler.MaxEntryCalories (entryCaloriesInRange)", kind: upperLimit,
			goLimit: MaxEntryCalories, sqlLimit: 9999, exact: true,
			probe: probeEntryCalories, probeStep: 1,
			site: inlineCheck, anchor: "calorie_entries_amount_range", literal: "amount <= 9999",
		},
		{
			what: "-handler.MaxEntryCalories (entryCaloriesInRange)", kind: lowerLimit,
			goLimit: -MaxEntryCalories, sqlLimit: -9999, exact: true,
			probe: probeEntryCalories, probeStep: 1,
			site: inlineCheck, anchor: "calorie_entries_amount_range", literal: "amount >= -9999",
		},

		// ---- calorie_entries.<macro>_g (x5) -----------------------------
		// The five macro CHECKs are generated from one template; the template
		// is the anchor and TestMacroCheckFamiliesAreUniform pins the names.
		{
			what: "handler.MaxEntryMacro (multiplyMacro)", kind: upperLimit,
			goLimit: MaxEntryMacro, sqlLimit: 999, exact: true,
			probe: probeMacro, probeStep: 1,
			site: inlineCheck, anchor: "ALTER TABLE calorie_entries ADD CONSTRAINT %s", literal: "<= 999",
		},
		{
			what: "handler macro floor (multiplyMacro)", kind: lowerLimit,
			goLimit: 0, sqlLimit: 0, exact: true,
			probe: probeMacro, probeStep: 1,
			site: inlineCheck, anchor: "ALTER TABLE calorie_entries ADD CONSTRAINT %s", literal: ">= 0",
		},

		// ---- saved_foods.amount / saved_foods.<macro> --------------------
		{
			what: "handler.MaxEntryCalories (saved foods)", kind: upperLimit,
			goLimit: MaxEntryCalories, sqlLimit: 9999, exact: true,
			probe: probeSavedAmount, probeStep: 1,
			site: goTableCheck, anchor: "saved_foods_amount_range", literal: "amount <= 9999",
		},
		{
			what: "-handler.MaxEntryCalories (saved foods)", kind: lowerLimit,
			goLimit: -MaxEntryCalories, sqlLimit: -9999, exact: true,
			probe: probeSavedAmount, probeStep: 1,
			site: goTableCheck, anchor: "saved_foods_amount_range", literal: "amount >= -9999",
		},
		{
			what: "handler.MaxEntryMacro (saved foods)", kind: upperLimit,
			goLimit: MaxEntryMacro, sqlLimit: 999, exact: true,
			probe: probeMacro, probeStep: 1,
			site: goTableCheck, anchor: "saved_foods_protein_range", literal: "protein_g <= 999",
		},
		{
			what: "handler macro floor (saved foods)", kind: lowerLimit,
			goLimit: 0, sqlLimit: 0, exact: true,
			probe: probeMacro, probeStep: 1,
			site: goTableCheck, anchor: "saved_foods_protein_range", literal: "protein_g >= 0",
		},

		// ---- weight_entries.weight ---------------------------------------
		{
			what: "service.ParseWeight lower bound", kind: lowerLimit,
			goLimit: 0, goExclusive: true, sqlLimit: 0, exact: true,
			probe: probeWeight, probeStep: 0.01,
			site: inlineCheck, anchor: "weight_entries_positive", literal: "weight > 0",
		},
		{
			what: "service.MaxWeight", kind: upperLimit,
			goLimit: service.MaxWeight, sqlLimit: 9999.99,
			widerWhy: "MaxWeight is a plausibility cap far below what NUMERIC(6,2) holds; " +
				"the column only has to be wide enough that the Go bound is reachable",
			probe: probeWeight, probeStep: 0.01,
			site: columnType, anchor: "weight NUMERIC(6, 2) NOT NULL", literal: "NUMERIC(6, 2)",
		},

		// ---- weight_entries.body_fat --------------------------------------
		{
			what: "service.MaxBodyFatPct", kind: upperLimit,
			goLimit: service.MaxBodyFatPct, sqlLimit: 75, exact: true,
			probe: probeBodyFat, probeStep: 0.1,
			site: inlineCheck, anchor: "weight_entries_body_fat_range", literal: "body_fat <= 75",
		},
		{
			what: "service.ParseBodyFat lower bound", kind: lowerLimit,
			goLimit: 0, goExclusive: true, sqlLimit: 0, exact: true,
			probe: probeBodyFat, probeStep: 0.1,
			site: inlineCheck, anchor: "weight_entries_body_fat_range", literal: "body_fat > 0",
		},

		// ---- users.height_cm ----------------------------------------------
		{
			what: "validateHeightCm", kind: lowerLimit,
			goLimit: 50, sqlLimit: 50, exact: true,
			probe: probeHeight, probeStep: 0.1,
			site: goTableCheck, anchor: "users_height_cm_range", literal: "height_cm >= 50",
		},
		{
			what: "validateHeightCm", kind: upperLimit,
			goLimit: 300, sqlLimit: 300, exact: true,
			probe: probeHeight, probeStep: 0.1,
			site: goTableCheck, anchor: "users_height_cm_range", literal: "height_cm <= 300",
		},

		// ---- users.birth_year -----------------------------------------------
		{
			what: "validateBirthYear", kind: lowerLimit,
			goLimit: 1900, sqlLimit: 1900, exact: true,
			probe: probeBirth, probeStep: 1,
			site: goTableCheck, anchor: "users_birth_year_range", literal: "birth_year >= 1900",
		},
		{
			what: "validateBirthYear (currentYear-10)", kind: upperLimit,
			goLimit: float64(time.Now().Year() - 10), sqlLimit: 2200,
			widerWhy: "the Go bound moves with the calendar (no under-10s); the CHECK is a fixed " +
				"sanity ceiling, so it must stay above any year the Go side will ever allow",
			probe: probeBirth, probeStep: 1,
			site: goTableCheck, anchor: "users_birth_year_range", literal: "birth_year <= 2200",
		},

		// ---- handler.minDateYear / maxDateYear -------------------------------
		// isValidDate's year window has no CHECK of its own (the columns are
		// DATE, which spans 4713 BC..5874897 AD), but it is the same "plausible
		// calendar year" range as users_birth_year_range and drifting the two
		// apart would be just as silent.
		{
			what: "handler.minDateYear (isValidDate)", kind: lowerLimit,
			goLimit: minDateYear, sqlLimit: 1900, exact: true,
			probe: probeDateYear, probeStep: 1,
			site: goTableCheck, anchor: "users_birth_year_range", literal: "birth_year >= 1900",
		},
		{
			what: "handler.maxDateYear (isValidDate)", kind: upperLimit,
			goLimit: maxDateYear, sqlLimit: 2200, exact: true,
			probe: probeDateYear, probeStep: 1,
			site: goTableCheck, anchor: "users_birth_year_range", literal: "birth_year <= 2200",
		},

		// ---- weight_goals.rate_kg_per_week ------------------------------------
		{
			what: "validateRateKgPerWeek", kind: upperLimit,
			goLimit: 99, sqlLimit: 99.99,
			widerWhy: "99 is the round number below the NUMERIC(4,2) ceiling of 99.99; the point " +
				"of the bound is only that it stays under the column's ceiling",
			probe: probeRate, probeStep: 0.01,
			site: columnType, anchor: "rate_kg_per_week NUMERIC(4,2)", literal: "NUMERIC(4,2)",
		},
		{
			what: "validateRateKgPerWeek lower bound", kind: lowerLimit,
			goLimit: 0, goExclusive: true, sqlLimit: -99.99,
			widerWhy: "there is NO CHECK on the sign of rate_kg_per_week — the column would happily " +
				"store a negative rate, and only the Go validator stops it",
			probe: probeRate, probeStep: 0.01,
			site: columnType, anchor: "rate_kg_per_week NUMERIC(4,2)", literal: "NUMERIC(4,2)",
		},

		// ---- weight_goals.target_weight ----------------------------------------
		{
			what: "validateTargetWeight lower bound", kind: lowerLimit,
			goLimit: 0, goExclusive: true, sqlLimit: 0, exact: true,
			probe: probeTargetWeight, probeStep: 0.01,
			site: inlineCheck, anchor: "weight_goals_positive", literal: "target_weight > 0",
		},
		{
			what: "validateTargetWeight (service.MaxWeight)", kind: upperLimit,
			goLimit: service.MaxWeight, sqlLimit: 9999.99,
			widerWhy: "same plausibility cap as ParseWeight, well inside what NUMERIC(6,2) holds",
			probe:    probeTargetWeight, probeStep: 0.01,
			site: columnType, anchor: "target_weight NUMERIC(6,2)", literal: "NUMERIC(6,2)",
		},
	}
}

// TestGoBoundsMatchMigrationLiterals is the no-database half of the drift
// guard: every Go limit is checked against the literal written next to the
// matching CHECK constraint (or column type) in internal/database/migrations.go.
func TestGoBoundsMatchMigrationLiterals(t *testing.T) {
	src := migrationSource(t)

	for _, b := range goBounds(t) {
		t.Run(b.what+" ("+b.kind.String()+")", func(t *testing.T) {
			sql := constraintText(t, src, b.site, b.anchor)

			// 1. The schema still says what this table claims it says.
			if !strings.Contains(sql, b.literal) {
				t.Fatalf("the schema no longer contains %q.\n  anchored SQL: %s\n"+
					"  Either the constraint changed and this table must follow, or the Go bound %s must.",
					b.literal, sql, b.what)
			}

			// 2. The table is honest about the number it claims the SQL holds.
			if b.site == columnType {
				max := numericColumnMax(t, b.literal)
				want := max
				if b.kind == lowerLimit {
					want = -max
				}
				if !nearly(b.sqlLimit, want) {
					t.Fatalf("%s holds %s..%s, but this table records the %s limit as %s",
						b.literal, fmtNum(-max), fmtNum(max), b.kind, fmtNum(b.sqlLimit))
				}
			} else if !strings.Contains(b.literal, fmtNum(b.sqlLimit)) {
				t.Fatalf("this table records the SQL %s limit as %s, but the literal it points at is %q",
					b.kind, fmtNum(b.sqlLimit), b.literal)
			}

			// 3. Go must never accept what the database rejects. This is the
			//    direction that turns a 400 into a 500.
			tooLoose := b.goLimit > b.sqlLimit
			if b.kind == lowerLimit {
				tooLoose = b.goLimit < b.sqlLimit
			}
			if tooLoose {
				t.Fatalf("%s accepts down/up to %s but the database %s limit is %s: "+
					"a value in between passes validation and then 500s on INSERT",
					b.what, fmtNum(b.goLimit), b.kind, fmtNum(b.sqlLimit))
			}

			// 4. Where the two are meant to be the same number, they must be.
			//    Where they are not, the row has to say why.
			if b.exact {
				if !nearly(b.goLimit, b.sqlLimit) {
					t.Fatalf("%s %s limit is %s but %q is %s; they are meant to be the same number",
						b.what, b.kind, fmtNum(b.goLimit), b.anchor, fmtNum(b.sqlLimit))
				}
				// An exact pair must agree on strictness too: `weight > 0` and
				// `weight >= 0` are the same number and different constraints.
				if b.site != columnType {
					sqlInclusive := strings.Contains(b.literal, ">=") || strings.Contains(b.literal, "<=")
					if sqlInclusive == b.goExclusive {
						t.Fatalf("%s %s the boundary value %s, but the CHECK says %q",
							b.what, map[bool]string{true: "excludes", false: "includes"}[b.goExclusive],
							fmtNum(b.goLimit), b.literal)
					}
				}
			} else if b.widerWhy == "" {
				t.Fatalf("%s is not an exact match with the database (%s vs %s) and gives no reason",
					b.what, fmtNum(b.goLimit), fmtNum(b.sqlLimit))
			}

			// 5. The VALIDATOR, not just the constant. A bound that is only
			//    ever compared against itself would still pass steps 1-4 after
			//    someone stopped applying it (exactly the #305 defect: the
			//    constant existed, validateTargetWeight ignored it).
			if b.probe == nil {
				return
			}
			inward := 1
			if b.kind == upperLimit {
				inward = -1
			}
			in, out := b.goLimit, gridStep(b.goLimit, b.probeStep, -inward)
			if b.goExclusive {
				// The boundary itself is rejected; the first accepted value is
				// one step inside it.
				in, out = gridStep(b.goLimit, b.probeStep, inward), b.goLimit
			}
			if !b.probe(in) {
				t.Errorf("the validator rejects %s, which this table records as inside its %s bound of %s",
					fmtNum(in), b.kind, fmtNum(b.goLimit))
			}
			if b.probe(out) {
				t.Errorf("the validator accepts %s, past the %s bound of %s this table records for it: "+
					"the bound is no longer being applied, and the row above is comparing a constant to itself",
					fmtNum(out), b.kind, fmtNum(b.goLimit))
			}
		})
	}
}

// TestMacroCheckFamiliesAreUniform pins the two families of repeated CHECKs.
// The rows above only anchor one member of each; if a sixth macro is added to
// calorie_entries, or one saved_foods macro is given a different ceiling, that
// member would otherwise never be looked at.
func TestMacroCheckFamiliesAreUniform(t *testing.T) {
	src := migrationSource(t)

	for _, name := range []string{
		"calorie_entries_protein_g_range",
		"calorie_entries_carbs_g_range",
		"calorie_entries_fat_g_range",
		"calorie_entries_fiber_g_range",
		"calorie_entries_sugar_g_range",
	} {
		if !strings.Contains(src, `"`+name+`"`) {
			t.Errorf("macro CHECK %s is gone from %s; the 0..%d bound is no longer enforced for it",
				name, migrationsSourcePath, MaxEntryMacro)
		}
	}

	for _, col := range []string{"protein", "carbs", "fat", "fiber", "sugar"} {
		expr := constraintText(t, src, goTableCheck, "saved_foods_"+col+"_range")
		for _, want := range []string{
			col + "_g >= " + fmtNum(0),
			col + "_g <= " + fmtNum(MaxEntryMacro),
		} {
			if !strings.Contains(expr, want) {
				t.Errorf("saved_foods_%s_range is %q, want it to contain %q (handler.MaxEntryMacro = %d)",
					col, expr, want, MaxEntryMacro)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Enum sets
// ---------------------------------------------------------------------------

var sqlStringLiteral = regexp.MustCompile(`'([^']*)'`)

// enumPair pins a Go set of accepted strings against the IN (...) list of the
// CHECK that backs it. Set EQUALITY is the assertion, not overlap: adding a
// value to the Go map without adding it to the CHECK is a 500, and adding it to
// the CHECK without adding it to the map is a value nothing can ever store.
type enumPair struct {
	what     string
	goValues []string
	accepts  func(string) bool // the Go validator, when there is one
	site     sqlSite
	anchor   string
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEnumSetsMatchMigrationCHECKs(t *testing.T) {
	src := migrationSource(t)

	pairs := []enumPair{
		{
			what: "handler.validSexes", goValues: sortedKeys(validSexes),
			accepts: func(s string) bool { return validateSex(&s) },
			site:    goTableCheck, anchor: "users_sex_valid",
		},
		{
			what: "handler.validActivityLevels", goValues: sortedKeys(validActivityLevels),
			accepts: func(s string) bool { return validateActivityLevel(&s) },
			site:    goTableCheck, anchor: "users_activity_valid",
		},
		{
			what: "handler.validatePaceMode", goValues: []string{"date", "rate"},
			accepts: validatePaceMode,
			site:    inlineCheck, anchor: "pace_mode TEXT NOT NULL",
		},
		{
			// No Go validator: these are the three literals
			// internal/service/weightgoal.go writes to weight_goals.status
			// (the 'active' default, MarkGoalAchieved, AbandonActiveGoal).
			what:     "weight_goals.status values written by service/weightgoal.go",
			goValues: []string{"abandoned", "achieved", "active"},
			site:     inlineCheck, anchor: "status TEXT NOT NULL DEFAULT 'active'",
		},
		{
			// No Go validator: the two literals internal/handler/settings.go
			// writes to account_links.status.
			what:     "account_links.status values written by handler/settings.go",
			goValues: []string{"accepted", "pending"},
			site:     inlineCheck, anchor: "status TEXT NOT NULL CHECK",
		},
	}

	for _, p := range pairs {
		t.Run(p.what, func(t *testing.T) {
			expr := constraintText(t, src, p.site, p.anchor)

			var sqlValues []string
			for _, m := range sqlStringLiteral.FindAllStringSubmatch(expr, -1) {
				sqlValues = append(sqlValues, m[1])
			}
			sort.Strings(sqlValues)

			want := append([]string(nil), p.goValues...)
			sort.Strings(want)

			if strings.Join(sqlValues, ",") != strings.Join(want, ",") {
				t.Fatalf("set mismatch — Go accepts %v, the CHECK accepts %v.\n  CHECK: %s\n"+
					"  A value in one set but not the other is either a 500 on INSERT or a value nothing can store.",
					want, sqlValues, expr)
			}

			if p.accepts == nil {
				return
			}
			for _, v := range want {
				if !p.accepts(v) {
					t.Errorf("the validator rejects %q even though the CHECK accepts it", v)
				}
			}
			if p.accepts("definitely-not-a-member") {
				t.Error("the validator accepts a value outside its own set; the CHECK would reject it as a 500")
			}
		})
	}
}

// TestAPITokenScopesConstraint covers the last row of the issue's table.
//
// api_tokens.scopes is TEXT[] with only api_tokens_scopes_not_empty
// (cardinality > 0) — there is no element-level CHECK, so the closed scope set
// is enforced in Go alone. That asymmetry is deliberate today but must not
// drift: if an element CHECK is ever added, its list has to equal
// service.AllScopes(), which this test pins automatically.
func TestAPITokenScopesConstraint(t *testing.T) {
	src := migrationSource(t)
	expr := constraintText(t, src, inlineCheck, "api_tokens_scopes_not_empty")

	var sqlValues []string
	for _, m := range sqlStringLiteral.FindAllStringSubmatch(expr, -1) {
		sqlValues = append(sqlValues, m[1])
	}

	if len(sqlValues) > 0 {
		sort.Strings(sqlValues)
		want := service.AllScopes()
		sort.Strings(want)
		if strings.Join(sqlValues, ",") != strings.Join(want, ",") {
			t.Errorf("api_tokens now constrains scope values to %v, but service.AllScopes() is %v",
				sqlValues, want)
		}
	} else if !strings.Contains(expr, "cardinality(scopes) > 0") {
		t.Errorf("api_tokens_scopes_not_empty is now %q; it no longer mirrors service.ErrNoScopes", expr)
	}

	// The Go side of the same pair: the closed set is the only element-level
	// gate there is, so it has to actually be closed.
	if _, err := service.ValidateScopes([]string{"entries:definitely-not-a-scope"}); err == nil {
		t.Error("ValidateScopes accepted an unknown scope; nothing else would stop it reaching the column")
	}
	if _, err := service.ValidateScopes(nil); err == nil {
		t.Error("ValidateScopes accepted an empty scope set; api_tokens_scopes_not_empty would 500 on INSERT")
	}
	seen := map[string]bool{}
	for _, s := range service.AllScopes() {
		if seen[s] {
			t.Errorf("scope %q is listed twice in service.ScopeDescriptions", s)
		}
		seen[s] = true
		if _, err := service.ValidateScopes([]string{s}); err != nil {
			t.Errorf("ValidateScopes rejects %q, which is in its own ScopeDescriptions: %v", s, err)
		}
	}
}
