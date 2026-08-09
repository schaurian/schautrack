package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	CookieName       = "schautrack.sid"
	AnonMaxAge       = 15 * time.Minute
	AuthMaxAge       = 30 * 24 * time.Hour
	PruneInterval    = 5 * time.Minute
	defaultStepUpTTL = 30 * time.Minute
)

// StepUpTTL is how long after fresh primary auth a session is considered
// "elevated" — i.e., allowed to perform sensitive auth-method changes
// (delete passkey, disable TOTP, change password/email, …) without
// re-authenticating. Defaults to 30 min; overridable via the STEP_UP_TTL
// environment variable (any value parseable by time.ParseDuration). The
// override exists for E2E tests that need a short window to exercise both
// the in-grace and expired paths.
var StepUpTTL = ParseStepUpTTL(os.Getenv("STEP_UP_TTL"))

// ParseStepUpTTL resolves a raw step_up_ttl value (env var or admin setting)
// into a duration, falling back to defaultStepUpTTL for anything empty,
// unparseable, or non-positive.
//
// It takes the raw string rather than reading the environment itself so the
// admin-settings validator that gates the same value (handler.validDuration)
// can be asserted against it — a value the validator accepts but this parser
// rejects means the admin sets a step-up window and silently gets 30m.
func ParseStepUpTTL(v string) time.Duration {
	if v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultStepUpTTL
}

// Session holds arbitrary data stored in the database.
type Session struct {
	ID        string
	Data      map[string]any
	MaxAge    time.Duration
	dirty     bool
	isNew     bool
	destroyed bool
}

func (s *Session) Set(key string, value any) {
	s.Data[key] = value
	s.dirty = true
}

func (s *Session) Get(key string) any {
	return s.Data[key]
}

func (s *Session) GetInt(key string) (int, bool) {
	v, ok := s.Data[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

func (s *Session) GetString(key string) string {
	v, ok := s.Data[key].(string)
	if !ok {
		return ""
	}
	return v
}

func (s *Session) Delete(key string) {
	delete(s.Data, key)
	s.dirty = true
}

func (s *Session) SetUserID(id int) {
	s.Set("userId", id)
	s.MaxAge = AuthMaxAge
	// Fresh primary auth doubles as step-up — the user just proved who they are.
	s.MarkStepUp()
}

func (s *Session) UserID() (int, bool) {
	return s.GetInt("userId")
}

// MarkStepUp records that the user has just completed strong primary auth.
// Sensitive auth-method changes consult HasRecentStepUp before proceeding.
func (s *Session) MarkStepUp() {
	// Stored as int (not int64) so GetInt can read it without a JSON round-trip.
	s.Set("step_up_at", int(time.Now().Unix()))
}

// HasRecentStepUp reports whether the session was elevated within StepUpTTL.
func (s *Session) HasRecentStepUp() bool {
	ts, ok := s.GetInt("step_up_at")
	if !ok {
		return false
	}
	return time.Since(time.Unix(int64(ts), 0)) < StepUpTTL
}

func (s *Session) MarkDirty() {
	s.dirty = true
}

// dbExecutor is the subset of *pgxpool.Pool the store uses. It exists so
// tests can substitute a fake and assert on exactly which writes the store
// attempted (or, for pristine sessions, that none were attempted at all)
// without a live Postgres.
type dbExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store manages sessions in PostgreSQL.
//
// There is deliberately no signing or encryption key here. Sessions are
// server-side: the cookie carries only the session ID, and the ID is 32 bytes
// of crypto/rand (see generateSID) whose authority is the row it addresses in
// the "session" table. Authenticity is "this row exists", which needs no key —
// unlike a signed-cookie design, where the cookie carries the session data
// itself and an HMAC is what stops the client editing it.
//
// The Node backend this replaced used express-session, whose secret HMAC-signed
// the SID cookie; the Go rewrite kept a SESSION_SECRET env var and a Store
// field for ~5 months without ever reading either. Both are gone. Rotating a
// secret never invalidated a session here — invalidateUserSessions does, and it
// is wired to every credential change.
type Store struct {
	pool dbExecutor
}

func NewStore(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool}
	go s.pruneLoop(context.Background())
	return s
}

// Load retrieves a session from the cookie or creates a new one.
func (s *Store) Load(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return s.newSession(), nil
	}

	sid := cookie.Value
	ctx := r.Context()

	var sessJSON []byte
	var expire time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT sess, expire FROM "session" WHERE sid = $1`, sid,
	).Scan(&sessJSON, &expire)

	if err != nil || time.Now().After(expire) {
		return s.newSession(), nil
	}

	data := make(map[string]any)
	dec := json.NewDecoder(strings.NewReader(string(sessJSON)))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return s.newSession(), nil
	}

	// Determine maxAge from stored data
	maxAge := AnonMaxAge
	if _, ok := data["userId"]; ok {
		maxAge = AuthMaxAge
	}

	return &Session{
		ID:     sid,
		Data:   data,
		MaxAge: maxAge,
	}, nil
}

// Save persists the session to the database and sets the cookie.
func (s *Store) Save(w http.ResponseWriter, r *http.Request, sess *Session) error {
	// If the session was explicitly destroyed during the request (e.g.
	// step-up lockout), don't resurrect it. Without this guard, the
	// middleware's deferred-save writer fires on the response write and
	// re-INSERTs the row plus re-sets the cookie that Destroy just cleared.
	if sess.destroyed {
		return nil
	}
	if !sess.dirty {
		if sess.isNew {
			// Pristine new session: no handler ever wrote data into it.
			// Persisting these would INSERT a "session" row and set a cookie
			// for every cookie-less request — k8s probes hit /api/health every
			// few seconds, and scanners can inflate the table at line rate.
			// Sessions become persistable the moment data is written (Set /
			// Delete / SetUserID / MarkStepUp / MarkDirty) or via Regenerate.
			return nil
		}
		// Loaded, unmodified session: still refresh cookie for rolling sessions
		s.setCookie(w, r, sess)
		return nil
	}

	sessJSON, err := json.Marshal(sess.Data)
	if err != nil {
		return err
	}

	expire := time.Now().Add(sess.MaxAge)

	_, err = s.pool.Exec(r.Context(), `
		INSERT INTO "session" (sid, sess, expire)
		VALUES ($1, $2::json, $3)
		ON CONFLICT (sid) DO UPDATE SET sess = $2::json, expire = $3
	`, sess.ID, string(sessJSON), expire)
	if err != nil {
		return err
	}

	s.setCookie(w, r, sess)
	return nil
}

// Destroy removes the session from the database and clears the cookie.
func (s *Store) Destroy(w http.ResponseWriter, r *http.Request, sess *Session) error {
	_, err := s.pool.Exec(r.Context(), `DELETE FROM "session" WHERE sid = $1`, sess.ID)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	// Mark so the middleware's deferred-save doesn't undo the destroy when
	// the handler subsequently writes the response body.
	sess.destroyed = true
	return nil
}

// Regenerate creates a new session ID, copies data, and deletes the old session.
// The caller must use SetSession(r, newSess) to tell the middleware to save it.
func (s *Store) Regenerate(r *http.Request, sess *Session) (*Session, error) {
	oldID := sess.ID
	newSess := &Session{
		ID:     generateSID(),
		Data:   make(map[string]any),
		MaxAge: sess.MaxAge,
		dirty:  true,
		isNew:  true,
	}
	// Copy data (don't share the map)
	for k, v := range sess.Data {
		newSess.Data[k] = v
	}

	// Delete old session from DB
	if _, err := s.pool.Exec(r.Context(), `DELETE FROM "session" WHERE sid = $1`, oldID); err != nil {
		slog.Error("failed to delete old session during regeneration", "error", err, "sid", oldID)
	}

	return newSess, nil
}

// newSession returns a pristine (not yet dirty) session. It is only persisted
// — and its cookie only set — once a handler actually writes data into it;
// see Save. Regenerate is the exception: it constructs its session with
// dirty=true because the old row was just deleted and the replacement must
// survive even if the handler writes no further data.
func (s *Store) newSession() *Session {
	return &Session{
		ID:     generateSID(),
		Data:   make(map[string]any),
		MaxAge: AnonMaxAge,
		isNew:  true,
	}
}

// requestSecure reports whether the request arrived over TLS, terminated
// either here or at the reverse proxy in front. Both Set-Cookie sites use it,
// so the clearing cookie in Destroy carries the same Secure flag as the
// session cookie it removes.
func requestSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *Store) setCookie(w http.ResponseWriter, r *http.Request, sess *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(sess.MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   requestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// pruneLoop deletes expired session rows every PruneInterval until stopped.
//
// It takes a context rather than looping forever so it has a shutdown path:
// NewStore passes context.Background(), preserving the previous
// runs-for-the-process-lifetime behaviour, while tests can pass a context they
// cancel. Without that, the loop is untestable — a bubbled test would wait on
// a goroutine that never exits, and an unbubbled one would wait five real
// minutes for the first tick.
func (s *Store) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(PruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if _, err := s.pool.Exec(execCtx, `DELETE FROM "session" WHERE expire < NOW()`); err != nil {
				slog.Error("failed to prune expired sessions", "error", err)
			}
			cancel()
		}
	}
}

func generateSID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
