package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	CookieName     = "schautrack.sid"
	AnonMaxAge     = 15 * time.Minute
	AuthMaxAge     = 30 * 24 * time.Hour
	PruneInterval  = 5 * time.Minute
)

// Session holds arbitrary data stored in the database.
type Session struct {
	ID      string
	Data    map[string]any
	MaxAge  time.Duration
	dirty   bool
	isNew   bool
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
}

func (s *Session) UserID() (int, bool) {
	return s.GetInt("userId")
}

func (s *Session) MarkDirty() {
	s.dirty = true
}

// Store manages sessions in PostgreSQL.
type Store struct {
	pool   *pgxpool.Pool
	secret string
	mu     sync.Mutex
}

func NewStore(pool *pgxpool.Pool, secret string) *Store {
	s := &Store{pool: pool, secret: secret}
	go s.pruneLoop()
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
	if !sess.dirty && !sess.isNew {
		// Still refresh cookie for rolling sessions
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
		SameSite: http.SameSiteLaxMode,
	})
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

func (s *Store) newSession() *Session {
	return &Session{
		ID:     generateSID(),
		Data:   make(map[string]any),
		MaxAge: AnonMaxAge,
		dirty:  true,
		isNew:  true,
	}
}

func (s *Store) setCookie(w http.ResponseWriter, r *http.Request, sess *Session) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(sess.MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Store) pruneLoop() {
	ticker := time.NewTicker(PruneInterval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := s.pool.Exec(ctx, `DELETE FROM "session" WHERE expire < NOW()`); err != nil {
			slog.Error("failed to prune expired sessions", "error", err)
		}
		cancel()
	}
}

func generateSID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
