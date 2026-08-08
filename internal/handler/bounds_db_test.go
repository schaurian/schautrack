package handler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/service"
)

// The behavioural half of the drift guard (see bounds_test.go for the pure-Go
// half and for why any of this exists).
//
// bounds_test.go compares Go constants to SQL literals it scrapes out of
// migrations.go. That catches an edit to one side of a pair, but it is still a
// hand-maintained transcription of the schema: get a row wrong and it pins the
// wrong thing.
//
// This file has no transcription in it. For each pair it BISECTS the real Go
// validator to find the exact value where it flips, then asks a real Postgres
// what it does with that value and with the value one step past it:
//
//	the value the Go validator accepts   -> the database MUST accept
//	the value one step past it           -> the database MUST reject
//
// The first direction is the 500-instead-of-400 bug. The second is the
// silently-rejected-legitimate-value bug. Neither needs a literal written down
// anywhere, so this half stays correct even when someone changes both sides
// consistently but wrongly.
//
// Gated on TEST_DATABASE_URL exactly like internal/database's integration
// tests. Since PR #325 CI sets it, so this runs on every build.

// boundaryProbe finds where a validator flips, on a grid of 1/scale.
//
// The predicate must be true on one contiguous run of the grid (every bound in
// this app is a plain range), which is what makes a bisection valid.
type boundaryProbe struct {
	ok    func(float64) bool
	scale float64 // 1 for integers, 10 for tenths, 100 for hundredths
}

// extreme returns the largest (upper) or smallest (lower) value the validator
// accepts, searching outward from a value it is known to accept.
func (p boundaryProbe) extreme(t *testing.T, kind limitKind, from float64, span int) float64 {
	t.Helper()
	if !p.ok(from) {
		t.Fatalf("the validator rejects %s, which the search has to start from", fmtNum(from))
	}
	dir := 1
	if kind == lowerLimit {
		dir = -1
	}
	// lo is known-accepted, hi is known-rejected, both in grid units from `from`.
	lo, hi := 0, span
	if p.ok(p.at(from, dir*span)) {
		t.Fatalf("the validator still accepts %s, %d steps out: it has no %s bound at all, "+
			"so the database is the only thing standing between the user and a 500",
			fmtNum(p.at(from, dir*span)), span, kind)
	}
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if p.ok(p.at(from, dir*mid)) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return p.at(from, dir*lo)
}

// at returns `from` moved by steps grid units, computed in integer units so the
// result is the double nearest the intended decimal.
func (p boundaryProbe) at(from float64, steps int) float64 {
	return (math.Round(from*p.scale) + float64(steps)) / p.scale
}

func (p boundaryProbe) next(v float64, kind limitKind) float64 {
	if kind == lowerLimit {
		return p.at(v, -1)
	}
	return p.at(v, 1)
}

// dbBound is one Go bound and the write that puts a value through it.
type dbBound struct {
	what  string
	kind  limitKind
	probe boundaryProbe
	from  float64 // a value the validator accepts, to bisect outward from
	span  int     // grid units to search
	write func(ctx context.Context, tx pgx.Tx, userID int, v float64) error
	// beyondDB is set when the column is deliberately WIDER than the Go bound
	// (e.g. NUMERIC(6,2) holds 9999.99 while ParseWeight caps at 1500). The
	// step past the Go bound is then legitimately accepted by the database, so
	// the reject-side assertion uses this value — past the column's own limit —
	// instead. Its purpose is to prove the column limit is still where the Go
	// bound's comment claims it is.
	beyondDB *float64
	whyWider string
}

func f(v float64) *float64 { return &v }

func dbBounds() []dbBound {
	insertEntry := func(col string) func(context.Context, pgx.Tx, int, float64) error {
		return func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
			_, err := tx.Exec(ctx, fmt.Sprintf(
				`INSERT INTO calorie_entries (user_id, entry_date, amount, %s) VALUES ($1, CURRENT_DATE, $2, $3)`, col),
				userID, 100, int(math.Round(v)))
			return err
		}
	}
	return []dbBound{
		{
			what: "handler.MaxEntryCalories -> calorie_entries.amount", kind: upperLimit,
			probe: boundaryProbe{ok: probeEntryCalories, scale: 1}, from: 0, span: 1 << 20,
			write: func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO calorie_entries (user_id, entry_date, amount) VALUES ($1, CURRENT_DATE, $2)`,
					userID, int(math.Round(v)))
				return err
			},
		},
		{
			what: "-handler.MaxEntryCalories -> calorie_entries.amount", kind: lowerLimit,
			probe: boundaryProbe{ok: probeEntryCalories, scale: 1}, from: 0, span: 1 << 20,
			write: func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO calorie_entries (user_id, entry_date, amount) VALUES ($1, CURRENT_DATE, $2)`,
					userID, int(math.Round(v)))
				return err
			},
		},
		{
			what: "handler.MaxEntryMacro -> calorie_entries.protein_g", kind: upperLimit,
			probe: boundaryProbe{ok: probeMacro, scale: 1}, from: 1, span: 1 << 20,
			write: insertEntry("protein_g"),
		},
		{
			what: "handler macro floor -> calorie_entries.protein_g", kind: lowerLimit,
			probe: boundaryProbe{ok: probeMacro, scale: 1}, from: 1, span: 1 << 20,
			write: insertEntry("protein_g"),
		},
		{
			what: "handler.MaxEntryCalories -> saved_foods.amount", kind: upperLimit,
			probe: boundaryProbe{ok: probeSavedAmount, scale: 1}, from: 0, span: 1 << 20,
			write: func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO saved_foods (user_id, name, amount) VALUES ($1, 'bounds-drift-probe', $2)`,
					userID, int(math.Round(v)))
				return err
			},
		},
		{
			what: "handler.MaxEntryMacro -> saved_foods.protein_g", kind: upperLimit,
			probe: boundaryProbe{ok: probeMacro, scale: 1}, from: 1, span: 1 << 20,
			write: func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO saved_foods (user_id, name, protein_g) VALUES ($1, 'bounds-drift-probe', $2)`,
					userID, int(math.Round(v)))
				return err
			},
		},
		{
			// The #302 pair: a positive input that rounds to 0 used to be
			// reported as valid and then hit weight_entries_positive as a 500.
			what: "service.ParseWeight floor -> weight_entries.weight", kind: lowerLimit,
			probe: boundaryProbe{ok: probeWeight, scale: 1000}, from: 1, span: 1 << 22,
			write: insertWeight(""),
		},
		{
			what: "service.MaxWeight -> weight_entries.weight", kind: upperLimit,
			probe: boundaryProbe{ok: probeWeight, scale: 1000}, from: 1, span: 1 << 22,
			write: insertWeight(""), beyondDB: f(10000),
			whyWider: "NUMERIC(6,2) holds 9999.99; MaxWeight is a much lower plausibility cap",
		},
		{
			what: "service.MaxBodyFatPct -> weight_entries.body_fat", kind: upperLimit,
			probe: boundaryProbe{ok: probeBodyFat, scale: 10}, from: 1, span: 1 << 20,
			write: insertWeight("body_fat"),
		},
		{
			what: "service.ParseBodyFat floor -> weight_entries.body_fat", kind: lowerLimit,
			probe: boundaryProbe{ok: probeBodyFat, scale: 100}, from: 1, span: 1 << 20,
			write: insertWeight("body_fat"),
		},
		{
			what: "validateHeightCm -> users.height_cm", kind: lowerLimit,
			probe: boundaryProbe{ok: probeHeight, scale: 10}, from: 170, span: 1 << 20,
			write: updateUser("height_cm"),
		},
		{
			what: "validateHeightCm -> users.height_cm", kind: upperLimit,
			probe: boundaryProbe{ok: probeHeight, scale: 10}, from: 170, span: 1 << 20,
			write: updateUser("height_cm"),
		},
		{
			what: "validateBirthYear -> users.birth_year", kind: lowerLimit,
			probe: boundaryProbe{ok: probeBirth, scale: 1}, from: 1990, span: 1 << 12,
			write: updateUserInt("birth_year"),
		},
		{
			what: "validateBirthYear -> users.birth_year", kind: upperLimit,
			probe: boundaryProbe{ok: probeBirth, scale: 1}, from: 1990, span: 1 << 12,
			write: updateUserInt("birth_year"), beyondDB: f(2201),
			whyWider: "the CHECK ceiling is a fixed 2200; the Go ceiling is currentYear-10 and moves",
		},
		{
			what: "validateRateKgPerWeek -> weight_goals.rate_kg_per_week", kind: upperLimit,
			probe: boundaryProbe{ok: probeRate, scale: 100}, from: 1, span: 1 << 20,
			write: insertGoal("rate_kg_per_week"), beyondDB: f(100),
			whyWider: "NUMERIC(4,2) holds 99.99; the Go cap is the round 99 below it",
		},
		{
			what: "validateRateKgPerWeek floor -> weight_goals.rate_kg_per_week", kind: lowerLimit,
			probe: boundaryProbe{ok: probeRate, scale: 100}, from: 1, span: 1 << 20,
			write: insertGoal("rate_kg_per_week"), beyondDB: f(-100),
			whyWider: "there is no CHECK on the sign of rate_kg_per_week at all — only the Go " +
				"validator stops a negative rate, so the column accepts anything down to -99.99",
		},
		{
			// The #305 pair: validateTargetWeight was unbounded, so a target
			// weight past NUMERIC(6,2) 500'd on INSERT.
			what: "validateTargetWeight -> weight_goals.target_weight", kind: upperLimit,
			probe: boundaryProbe{ok: probeTargetWeight, scale: 1000}, from: 1, span: 1 << 22,
			write: insertGoal("target_weight"), beyondDB: f(10000),
			whyWider: "NUMERIC(6,2) holds 9999.99; the Go cap is service.MaxWeight",
		},
		{
			what: "validateTargetWeight floor -> weight_goals.target_weight", kind: lowerLimit,
			probe: boundaryProbe{ok: probeTargetWeight, scale: 1000}, from: 1, span: 1 << 22,
			write: insertGoal("target_weight"),
		},
	}
}

func insertWeight(extraCol string) func(context.Context, pgx.Tx, int, float64) error {
	return func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
		if extraCol == "" {
			_, err := tx.Exec(ctx,
				`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES ($1, CURRENT_DATE, $2)`,
				userID, v)
			return err
		}
		_, err := tx.Exec(ctx, fmt.Sprintf(
			`INSERT INTO weight_entries (user_id, entry_date, weight, %s) VALUES ($1, CURRENT_DATE, 80, $2)`, extraCol),
			userID, v)
		return err
	}
}

func updateUser(col string) func(context.Context, pgx.Tx, int, float64) error {
	return func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
		return exactlyOneRow(tx.Exec(ctx,
			fmt.Sprintf(`UPDATE users SET %s = $2 WHERE id = $1`, col), userID, v))
	}
}

func updateUserInt(col string) func(context.Context, pgx.Tx, int, float64) error {
	return func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
		return exactlyOneRow(tx.Exec(ctx,
			fmt.Sprintf(`UPDATE users SET %s = $2 WHERE id = $1`, col), userID, int(math.Round(v))))
	}
}

func insertGoal(col string) func(context.Context, pgx.Tx, int, float64) error {
	return func(ctx context.Context, tx pgx.Tx, userID int, v float64) error {
		if col == "target_weight" {
			_, err := tx.Exec(ctx,
				`INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode)
				 VALUES ($1, 100, CURRENT_DATE, $2, 'rate')`, userID, v)
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode, rate_kg_per_week)
			 VALUES ($1, 100, CURRENT_DATE, 90, 'rate', $2)`, userID, v)
		return err
	}
}

// exactlyOneRow turns a no-op UPDATE into an error. Without it an UPDATE that
// matched nothing would look exactly like a value the database happily
// accepted, and every reject-side assertion would pass for the wrong reason.
func exactlyOneRow(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("updated %d rows, want 1", tag.RowsAffected())
	}
	return nil
}

// TestBoundsAgreeWithLiveDatabase drives every Go validator to its edge and
// checks a real Postgres agrees on both sides of that edge.
func TestBoundsAgreeWithLiveDatabase(t *testing.T) {
	ctx, pool, userID := boundsTestDB(t)

	for _, b := range dbBounds() {
		t.Run(b.what+" ("+b.kind.String()+")", func(t *testing.T) {
			// 1. Where does the Go validator actually flip? No literal from
			//    the schema, and none from bounds_test.go, is used here.
			edge := b.probe.extreme(t, b.kind, b.from, b.span)
			past := b.probe.next(edge, b.kind)

			// 2. Everything Go accepts, the database must accept. This is the
			//    direction that turns a 400 into a 500 in production.
			if err := attempt(ctx, t, pool, userID, b.write, edge); err != nil {
				t.Fatalf("the validator accepts %s but the database refuses it: %v\n"+
					"  A request carrying that value passes validation and then 500s on INSERT.",
					fmtNum(edge), err)
			}

			// 3. Everything Go rejects, the database must also reject —
			//    otherwise the Go bound is silently refusing values the schema
			//    was perfectly happy to store, and nothing says why.
			reject, why := past, ""
			if b.beyondDB != nil {
				reject, why = *b.beyondDB, b.whyWider
				// The column really is wider here, so first prove the Go bound
				// is the stricter one rather than an accidental match.
				if err := attempt(ctx, t, pool, userID, b.write, past); err != nil {
					t.Fatalf("this pair is marked as deliberately wider on the database side (%s), "+
						"but the database rejects %s, one step past the Go bound: %v\n"+
						"  The two are actually the same bound; drop beyondDB and assert them as an exact pair.",
						why, fmtNum(past), err)
				}
			}
			if err := attempt(ctx, t, pool, userID, b.write, reject); err == nil {
				msg := fmt.Sprintf("the validator rejects %s but the database stores it happily",
					fmtNum(reject))
				if why != "" {
					msg = fmt.Sprintf("the database accepted %s, past the column limit this bound exists to stay inside (%s)",
						fmtNum(reject), why)
				}
				t.Fatalf("%s\n  Either the Go bound is needlessly strict, or the schema lost a constraint.", msg)
			}
		})
	}
}

// attempt runs one write inside a transaction that is always rolled back, so
// the probes leave nothing behind and cannot collide with each other's unique
// indexes (one weight entry per user per day, one active goal per user).
func attempt(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID int,
	write func(context.Context, pgx.Tx, int, float64) error, v float64) error {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	return write(ctx, tx, userID, v)
}

// ---------------------------------------------------------------------------
// Enum sets, read back out of the live catalog
// ---------------------------------------------------------------------------

var pgTextLiteral = regexp.MustCompile(`'([^']*)'::text`)

// TestEnumSetsAgreeWithLiveDatabase compares each Go set against the CHECK as
// Postgres itself reports it, rather than against the migration source. Set
// EQUALITY is the assertion: a value in the Go set but not the CHECK is a 500,
// and a value in the CHECK but not the Go set can never be stored by anything.
func TestEnumSetsAgreeWithLiveDatabase(t *testing.T) {
	ctx, pool, userID := boundsTestDB(t)

	cases := []struct {
		what          string
		table, column string
		goValues      []string
		write         func(ctx context.Context, tx pgx.Tx, userID int, v string) error
	}{
		{
			what: "handler.validSexes", table: "users", column: "sex",
			goValues: sortedKeys(validSexes),
			write: func(ctx context.Context, tx pgx.Tx, userID int, v string) error {
				return exactlyOneRow(tx.Exec(ctx, `UPDATE users SET sex = $2 WHERE id = $1`, userID, v))
			},
		},
		{
			what: "handler.validActivityLevels", table: "users", column: "activity_level",
			goValues: sortedKeys(validActivityLevels),
			write: func(ctx context.Context, tx pgx.Tx, userID int, v string) error {
				return exactlyOneRow(tx.Exec(ctx, `UPDATE users SET activity_level = $2 WHERE id = $1`, userID, v))
			},
		},
		{
			what: "handler.validatePaceMode", table: "weight_goals", column: "pace_mode",
			goValues: []string{"date", "rate"},
			write: func(ctx context.Context, tx pgx.Tx, userID int, v string) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode)
					 VALUES ($1, 100, CURRENT_DATE, 90, $2)`, userID, v)
				return err
			},
		},
		{
			what:  "weight_goals.status written by service/weightgoal.go",
			table: "weight_goals", column: "status",
			goValues: []string{"abandoned", "achieved", "active"},
			write: func(ctx context.Context, tx pgx.Tx, userID int, v string) error {
				_, err := tx.Exec(ctx,
					`INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode, status)
					 VALUES ($1, 100, CURRENT_DATE, 90, 'rate', $2)`, userID, v)
				return err
			},
		},
		{
			what:  "account_links.status written by handler/settings.go",
			table: "account_links", column: "status",
			goValues: []string{"accepted", "pending"},
			write: func(ctx context.Context, tx pgx.Tx, userID int, v string) error {
				var otherID int
				if err := tx.QueryRow(ctx,
					`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`,
					fmt.Sprintf("bounds-drift-link-%d@handler.test", userID)).Scan(&otherID); err != nil {
					return err
				}
				_, err := tx.Exec(ctx,
					`INSERT INTO account_links (requester_id, target_id, status) VALUES ($1, $2, $3)`,
					userID, otherID, v)
				return err
			},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			sqlValues := checkLiterals(ctx, t, pool, c.table, c.column)
			want := append([]string(nil), c.goValues...)
			sort.Strings(want)

			if strings.Join(sqlValues, ",") != strings.Join(want, ",") {
				t.Fatalf("set mismatch — Go uses %v, %s.%s accepts %v.\n"+
					"  A value in the first set only is a 500 on write; a value in the second only can never be stored.",
					want, c.table, c.column, sqlValues)
			}

			// The catalog says what the CHECK is; these prove it behaves that way.
			for _, v := range want {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatalf("begin: %v", err)
				}
				err = c.write(ctx, tx, userID, v)
				tx.Rollback(ctx)
				if err != nil {
					t.Errorf("%s.%s rejected %q, which Go writes: %v", c.table, c.column, v, err)
				}
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			err = c.write(ctx, tx, userID, "bounds-drift-not-a-member")
			tx.Rollback(ctx)
			if err == nil {
				t.Errorf("%s.%s stored a value outside its own CHECK", c.table, c.column)
			}
		})
	}
}

// TestAPITokenScopesAgreeWithLiveDatabase is the scopes row of the issue's
// table. api_tokens.scopes carries only api_tokens_scopes_not_empty
// (cardinality > 0): the closed set of scope NAMES is enforced in Go alone. So
// the assertions here are (a) the database accepts every scope Go grants,
// (b) both sides reject the empty set, and (c) if an element-level CHECK is
// ever added, its list equals service.AllScopes().
func TestAPITokenScopesAgreeWithLiveDatabase(t *testing.T) {
	ctx, pool, userID := boundsTestDB(t)

	scopes := service.AllScopes()
	sort.Strings(scopes)

	if lits := checkLiterals(ctx, t, pool, "api_tokens", "scopes"); len(lits) > 0 {
		if strings.Join(lits, ",") != strings.Join(scopes, ",") {
			t.Errorf("api_tokens.scopes now constrains values to %v, but service.AllScopes() is %v",
				lits, scopes)
		}
	}

	insert := func(v []string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx,
			`INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes)
			 VALUES ($1, 'bounds-drift-probe', $2, 'st_probe', $3)`,
			userID, []byte("bounds-drift-probe-hash"), v)
		return err
	}

	// Every scope Go will grant has to survive the write.
	if err := insert(scopes); err != nil {
		t.Fatalf("api_tokens rejected the full scope set from service.AllScopes(): %v", err)
	}
	for _, s := range scopes {
		if err := insert([]string{s}); err != nil {
			t.Errorf("api_tokens rejected scope %q, which ValidateScopes grants: %v", s, err)
		}
	}

	// Both sides must refuse a scopeless token: Go with ErrNoScopes, the
	// database with api_tokens_scopes_not_empty.
	if _, err := service.ValidateScopes(nil); !errors.Is(err, service.ErrNoScopes) {
		t.Errorf("ValidateScopes(nil) = %v, want ErrNoScopes", err)
	}
	if err := insert([]string{}); err == nil {
		t.Error("api_tokens accepted a token with no scopes; api_tokens_scopes_not_empty is gone")
	}
}

// checkLiterals returns, sorted, every string literal appearing in the CHECK
// constraints on table that mention column — i.e. the enum set as Postgres
// itself reports it, with no reference to the migration source.
func checkLiterals(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table, column string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = $1::regclass AND contype = 'c'`, table)
	if err != nil {
		t.Fatalf("reading CHECK constraints on %s failed: %v", table, err)
	}
	defer rows.Close()

	mentionsColumn := regexp.MustCompile(`\b` + regexp.QuoteMeta(column) + `\b`)
	var out []string
	for rows.Next() {
		var def string
		if err := rows.Scan(&def); err != nil {
			t.Fatalf("scanning a constraint definition failed: %v", err)
		}
		if !mentionsColumn.MatchString(def) {
			continue
		}
		for _, m := range pgTextLiteral.FindAllStringSubmatch(def, -1) {
			out = append(out, m[1])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating constraint definitions failed: %v", err)
	}
	sort.Strings(out)
	return out
}

// boundsTestDB brings up the schema and a throwaway user to write against.
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests. Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/handler/ -run Bounds -v
func boundsTestDB(t *testing.T) (context.Context, *pgxpool.Pool, int) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	email := fmt.Sprintf("bounds-drift-%s@handler.test", strings.ToLower(t.Name()))
	cleanup := func() {
		pool.Exec(ctx, `DELETE FROM users WHERE email LIKE 'bounds-drift-%@handler.test'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}
	return ctx, pool, userID
}
