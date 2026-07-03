package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeDB implements dbExecutor and records every Exec statement, so tests can
// assert exactly which writes the store attempted — including that NONE were
// attempted — without a live Postgres.
type fakeDB struct {
	mu    sync.Mutex
	execs []string
	// row, when set, backs QueryRow's Scan (used to simulate an existing
	// session row). When nil, QueryRow behaves like a missing row.
	row func(dest ...any) error
}

func (f *fakeDB) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, strings.Join(strings.Fields(sql), " "))
	return pgconn.CommandTag{}, nil
}

func (f *fakeDB) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	if f.row == nil {
		return fakeRow{scan: func(...any) error { return pgx.ErrNoRows }}
	}
	return fakeRow{scan: f.row}
}

func (f *fakeDB) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.execs...)
}

type fakeRow struct{ scan func(dest ...any) error }

func (r fakeRow) Scan(dest ...any) error { return r.scan(dest...) }

func serveWithSession(t *testing.T, db *fakeDB, req *http.Request, handler http.HandlerFunc) *http.Response {
	t.Helper()
	// Construct the Store directly (not via NewStore) so no prune loop
	// goroutine leaks into the test.
	store := &Store{pool: db}
	rec := httptest.NewRecorder()
	Middleware(store)(handler).ServeHTTP(rec, req)
	return rec.Result()
}

// TestPristineSessionNotPersisted guards the write-amplification fix: a
// cookie-less request whose handler never writes session data (k8s probes on
// /api/health, scanners) must produce NO Set-Cookie header and NO database
// write. Before the fix, every such request INSERTed a "session" row.
func TestPristineSessionNotPersisted(t *testing.T) {
	db := &fakeDB{}
	req := httptest.NewRequest("GET", "/api/health", nil)

	resp := serveWithSession(t, db, req, func(w http.ResponseWriter, r *http.Request) {
		// Read-only session access must not count as "touched".
		sess := GetSession(r)
		_, _ = sess.UserID()
		_ = sess.GetString("csrfToken")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("pristine session must not set a cookie, got Set-Cookie: %v", cookies)
	}
	if execs := db.recorded(); len(execs) != 0 {
		t.Errorf("pristine session must not touch the database, got writes: %v", execs)
	}
}

// TestNewSessionWithDataPersisted proves the flip side: a new session that a
// handler actually writes to (captcha, pendingRegistration, CSRF token via
// sess.Set) must still be INSERTed and must still set the cookie.
func TestNewSessionWithDataPersisted(t *testing.T) {
	db := &fakeDB{}
	req := httptest.NewRequest("GET", "/api/captcha", nil)

	var sid string
	resp := serveWithSession(t, db, req, func(w http.ResponseWriter, r *http.Request) {
		sess := GetSession(r)
		sess.Set("captchaAnswer", "42")
		sid = sess.ID
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.Contains(cookies[0], CookieName+"="+sid) {
		t.Errorf("expected one %s cookie for sid %s, got %v", CookieName, sid, cookies)
	}
	execs := db.recorded()
	if len(execs) != 1 || !strings.Contains(execs[0], `INSERT INTO "session"`) {
		t.Errorf("expected exactly one session INSERT, got %v", execs)
	}
}

// TestLoadedSessionRollingRefresh pins the pre-existing rolling-session
// behavior: a request with a valid cookie whose handler doesn't modify the
// session still gets its cookie refreshed (sliding expiry) but causes no
// database write.
func TestLoadedSessionRollingRefresh(t *testing.T) {
	db := &fakeDB{
		row: func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{"userId": 7}`)
			*(dest[1].(*time.Time)) = time.Now().Add(time.Hour)
			return nil
		},
	}
	req := httptest.NewRequest("GET", "/api/entries", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "existing-sid"})

	resp := serveWithSession(t, db, req, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.Contains(cookies[0], CookieName+"=existing-sid") {
		t.Errorf("loaded session must keep its rolling cookie refresh, got %v", cookies)
	}
	if execs := db.recorded(); len(execs) != 0 {
		t.Errorf("unmodified loaded session must not write to the database, got %v", execs)
	}
}

// TestRegeneratedSessionPersisted pins Regenerate semantics: a regenerated
// session must be persisted and set its new cookie even if no data key is
// written afterwards (the old row was just DELETEd; losing the new one would
// log the user out).
func TestRegeneratedSessionPersisted(t *testing.T) {
	db := &fakeDB{
		row: func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{"userId": 7}`)
			*(dest[1].(*time.Time)) = time.Now().Add(time.Hour)
			return nil
		},
	}
	req := httptest.NewRequest("POST", "/api/auth/step-up", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "old-sid"})

	store := &Store{pool: db}
	var newSID string
	rec := httptest.NewRecorder()
	Middleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := GetSession(r)
		newSess, err := store.Regenerate(r, sess)
		if err != nil {
			t.Errorf("Regenerate failed: %v", err)
		}
		newSID = newSess.ID
		SetSession(r, newSess)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})).ServeHTTP(rec, req)
	resp := rec.Result()

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.Contains(cookies[0], CookieName+"="+newSID) {
		t.Errorf("expected cookie for regenerated sid %s, got %v", newSID, cookies)
	}
	execs := db.recorded()
	var sawDelete, sawInsert bool
	for _, e := range execs {
		if strings.Contains(e, `DELETE FROM "session"`) {
			sawDelete = true
		}
		if strings.Contains(e, `INSERT INTO "session"`) {
			sawInsert = true
		}
	}
	if !sawDelete || !sawInsert {
		t.Errorf("regeneration must DELETE the old row and INSERT the new one, got %v", execs)
	}
}

// TestDestroyedSessionNotResurrected pins the Destroy guard: after Destroy,
// the middleware's deferred save must not re-INSERT the row or re-set the
// session cookie (only the clearing cookie from Destroy itself remains).
func TestDestroyedSessionNotResurrected(t *testing.T) {
	db := &fakeDB{
		row: func(dest ...any) error {
			*(dest[0].(*[]byte)) = []byte(`{"userId": 7}`)
			*(dest[1].(*time.Time)) = time.Now().Add(time.Hour)
			return nil
		},
	}
	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "doomed-sid"})

	store := &Store{pool: db}
	rec := httptest.NewRecorder()
	Middleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := GetSession(r)
		if err := store.Destroy(w, r, sess); err != nil {
			t.Errorf("Destroy failed: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})).ServeHTTP(rec, req)
	resp := rec.Result()

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.Contains(cookies[0], CookieName+"=;") {
		t.Errorf("expected only the clearing cookie from Destroy, got %v", cookies)
	}
	for _, e := range db.recorded() {
		if strings.Contains(e, `INSERT INTO "session"`) {
			t.Errorf("destroyed session must not be re-INSERTed, got %v", db.recorded())
		}
	}
}
