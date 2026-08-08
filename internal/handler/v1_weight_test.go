package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// decodeWeightInput runs a raw body through the real v1 decoder, so these tests
// exercise Optional's UnmarshalJSON rather than a hand-built struct — the whole
// point of the type is that absent and explicit-null decode differently, and a
// literal `v1WeightInput{}` would assert nothing about that.
func decodeWeightInput(t *testing.T, raw string) v1WeightInput {
	t.Helper()
	var in v1WeightInput
	req := httptest.NewRequest(http.MethodPut, "/api/v1/weight/2026-08-08", strings.NewReader(raw))
	if prob := decodeV1(httptest.NewRecorder(), req, &in); prob != nil {
		t.Fatalf("decodeV1(%s) = problem %d %s", raw, prob.Status, prob.Detail)
	}
	return in
}

// TestV1WeightBodyFatOptionalStates pins the three-state mapping the public API
// promises. Absent-means-keep is the load-bearing one: a smart scale that
// reports weight only must never wipe a body fat recorded in the app for the
// same day.
func TestV1WeightBodyFatOptionalStates(t *testing.T) {
	t.Run("absent leaves the stored reading alone", func(t *testing.T) {
		in := decodeWeightInput(t, `{"weight":82.4}`)
		got, ok := bodyFatUpdate(in.BodyFat)
		if !ok {
			t.Fatal("a weight-only body was rejected")
		}
		if got != service.KeepBodyFat {
			t.Errorf("bodyFatUpdate = %+v, want KeepBodyFat — a weight-only writer would erase a reading", got)
		}
	})

	t.Run("explicit null clears it", func(t *testing.T) {
		in := decodeWeightInput(t, `{"weight":82.4,"body_fat":null}`)
		got, ok := bodyFatUpdate(in.BodyFat)
		if !ok {
			t.Fatal("an explicit null was rejected")
		}
		if !got.Set || got.Value != nil {
			t.Errorf("bodyFatUpdate = %+v, want {Set:true Value:nil}", got)
		}
	})

	t.Run("a number sets it", func(t *testing.T) {
		in := decodeWeightInput(t, `{"weight":82.4,"body_fat":22.5}`)
		got, ok := bodyFatUpdate(in.BodyFat)
		if !ok {
			t.Fatal("a valid percentage was rejected")
		}
		if !got.Set || got.Value == nil {
			t.Fatalf("bodyFatUpdate = %+v, want a value", got)
		}
		if *got.Value != 22.5 {
			t.Errorf("value = %v, want 22.5", *got.Value)
		}
	})

	// The column is NUMERIC(4,1) and ParseBodyFat rounds to match it. A client
	// computing a percentage in floating point routinely produces digits past
	// the first; those must round, not be rejected.
	t.Run("float noise rounds instead of failing", func(t *testing.T) {
		in := decodeWeightInput(t, `{"weight":82.4,"body_fat":22.499999999999996}`)
		got, ok := bodyFatUpdate(in.BodyFat)
		if !ok {
			t.Fatal("a percentage with float noise was rejected; a computed value must round")
		}
		if got.Value == nil || *got.Value != 22.5 {
			t.Errorf("value = %v, want 22.5", got.Value)
		}
	})

	for _, raw := range []string{
		`{"weight":82.4,"body_fat":0}`,
		`{"weight":82.4,"body_fat":-3}`,
		`{"weight":82.4,"body_fat":75.1}`,
		`{"weight":82.4,"body_fat":1000}`,
	} {
		t.Run("out of range rejected: "+raw, func(t *testing.T) {
			in := decodeWeightInput(t, raw)
			if got, ok := bodyFatUpdate(in.BodyFat); ok {
				t.Errorf("bodyFatUpdate = %+v, ok — the value is outside ParseBodyFat's range", got)
			}
		})
	}
}

// putWeightRequest drives PutWeightV1 directly, wiring the {date} path param
// chi would normally supply.
func putWeightRequest(t *testing.T, h *V1Handler, ctx context.Context, date, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/weight/"+date, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("date", date)
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.PutWeightV1(rec, req)
	return rec
}

// TestPutWeightV1RejectsOutOfRangeBodyFat is the guard against a 500.
//
// weight_entries carries a CHECK on the body_fat range; without validation in
// the handler an out-of-bounds percentage would reach the database and come
// back as a driver error, which dbFail turns into an opaque 500. The value must
// be rejected before anything touches the pool — which is exactly why this test
// can run with a nil pool and therefore runs in CI, unlike the round-trip below.
func TestPutWeightV1RejectsOutOfRangeBodyFat(t *testing.T) {
	h := &V1Handler{} // no pool: reaching one would panic and fail the test
	rec := putWeightRequest(t, h, context.Background(), "2026-08-08", `{"weight":82.4,"body_fat":140}`)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, apierr.ContentType)
	}

	var prob struct {
		Status        int    `json:"status"`
		Type          string `json:"type"`
		InvalidParams []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"invalid_params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	if prob.Status != http.StatusUnprocessableEntity {
		t.Errorf("problem.status = %d, want 422", prob.Status)
	}
	if len(prob.InvalidParams) != 1 || prob.InvalidParams[0].Name != "body_fat" {
		t.Errorf("invalid_params = %+v, want one naming body_fat", prob.InvalidParams)
	}
}

// TestV1WeightBodyFatRoundTrip walks the three Optional states through the real
// handlers and the real database, and pins the body_fat_enabled flip.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration tests:
//
//	docker run -d --rm --name pg-test -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:18
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' \
//	  go test ./internal/handler/ -run TestV1WeightBodyFatRoundTrip -v
func TestV1WeightBodyFatRoundTrip(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// database.NewPool, not pgxpool.New: it registers the codec that returns
	// DATE columns as "YYYY-MM-DD" strings, which every weight reader relies on.
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const email = "v1-body-fat@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified, weight_unit, body_fat_enabled)
		 VALUES ($1, 'x', true, 'kg', false) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	h := &V1Handler{Pool: pool}
	const date = "2026-08-08"

	// Reload the user the way RequireAPIToken would on each request, so the
	// handler sees the real body_fat_enabled rather than a stale copy.
	userCtx := func() context.Context {
		t.Helper()
		u := &model.User{ID: userID, Email: email, WeightUnit: "kg"}
		if err := pool.QueryRow(ctx,
			`SELECT body_fat_enabled FROM users WHERE id = $1`, userID).Scan(&u.BodyFatEnabled); err != nil {
			t.Fatalf("reloading the user failed: %v", err)
		}
		return middleware.WithTestUser(ctx, u)
	}
	decodeWeight := func(rec *httptest.ResponseRecorder) v1Weight {
		t.Helper()
		var got v1Weight
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not a weight: %v (%s)", err, rec.Body.String())
		}
		return got
	}
	storedBodyFat := func() *float64 {
		t.Helper()
		var pct *float64
		if err := pool.QueryRow(ctx,
			`SELECT body_fat FROM weight_entries WHERE user_id = $1 AND entry_date = $2`,
			userID, date).Scan(&pct); err != nil {
			t.Fatalf("reading body_fat back failed: %v", err)
		}
		return pct
	}
	bodyFatEnabled := func() bool {
		t.Helper()
		var on bool
		if err := pool.QueryRow(ctx, `SELECT body_fat_enabled FROM users WHERE id = $1`, userID).Scan(&on); err != nil {
			t.Fatalf("reading body_fat_enabled failed: %v", err)
		}
		return on
	}

	// 1. A number sets it — and switches the opt-in on, so the reading is not
	//    stored invisibly behind a preference the user never found.
	rec := putWeightRequest(t, h, userCtx(), date, `{"weight":82.4,"body_fat":22.5}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first write: status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeWeight(rec); got.BodyFat == nil || *got.BodyFat != 22.5 {
		t.Errorf("first write returned body_fat = %v, want 22.5", got.BodyFat)
	}
	if pct := storedBodyFat(); pct == nil || *pct != 22.5 {
		t.Errorf("stored body_fat = %v, want 22.5", pct)
	}
	if !bodyFatEnabled() {
		t.Error("writing a body fat via the API left body_fat_enabled false; the reading is invisible in the app")
	}

	// 2. Absent leaves it alone. This is the scale-integration case: a
	//    weight-only PUT for the same day must not erase the measurement.
	rec = putWeightRequest(t, h, userCtx(), date, `{"weight":82.1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("weight-only write: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeWeight(rec); got.BodyFat == nil || *got.BodyFat != 22.5 {
		t.Errorf("weight-only write returned body_fat = %v, want the stored 22.5", got.BodyFat)
	}
	if pct := storedBodyFat(); pct == nil || *pct != 22.5 {
		t.Errorf("a weight-only write changed the stored body_fat to %v; it must be left alone", pct)
	}

	// The readers must surface it too, or a client cannot mirror the app.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/weight/"+date, nil)
	getRctx := chi.NewRouteContext()
	getRctx.URLParams.Add("date", date)
	getRec := httptest.NewRecorder()
	h.GetWeightV1(getRec, getReq.WithContext(context.WithValue(userCtx(), chi.RouteCtxKey, getRctx)))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200 (body %s)", getRec.Code, getRec.Body.String())
	}
	if got := decodeWeight(getRec); got.BodyFat == nil || *got.BodyFat != 22.5 {
		t.Errorf("GET returned body_fat = %v, want 22.5", got.BodyFat)
	}

	listRec := httptest.NewRecorder()
	h.ListWeight(listRec, httptest.NewRequest(http.MethodGet, "/api/v1/weight", nil).WithContext(userCtx()))
	if listRec.Code != http.StatusOK {
		t.Fatalf("LIST: status = %d, want 200 (body %s)", listRec.Code, listRec.Body.String())
	}
	var page v1List[v1Weight]
	if err := json.Unmarshal(listRec.Body.Bytes(), &page); err != nil {
		t.Fatalf("list response is not a page: %v (%s)", err, listRec.Body.String())
	}
	if len(page.Data) != 1 {
		t.Fatalf("list returned %d readings, want 1", len(page.Data))
	}
	if page.Data[0].BodyFat == nil || *page.Data[0].BodyFat != 22.5 {
		t.Errorf("list returned body_fat = %v, want 22.5", page.Data[0].BodyFat)
	}

	// 3. Explicit null clears it — but must not switch the opt-in back off:
	//    other days may still carry readings.
	rec = putWeightRequest(t, h, userCtx(), date, `{"weight":82.1,"body_fat":null}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clearing write: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeWeight(rec); got.BodyFat != nil {
		t.Errorf("clearing write returned body_fat = %v, want null", *got.BodyFat)
	}
	if pct := storedBodyFat(); pct != nil {
		t.Errorf("stored body_fat = %v after an explicit null, want NULL", *pct)
	}
	if !bodyFatEnabled() {
		t.Error("clearing one day's body fat switched body_fat_enabled off; the flip is one-way")
	}

	// An out-of-range value is a 422 against a real database too — the CHECK
	// constraint must never be the thing that rejects it.
	rec = putWeightRequest(t, h, userCtx(), date, fmt.Sprintf(`{"weight":82.1,"body_fat":%g}`, service.MaxBodyFatPct+1))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("out-of-range write: status = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, apierr.ContentType)
	}
}
