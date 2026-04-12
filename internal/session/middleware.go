package session

import (
	"context"
	"net/http"
)

type contextKey string

const sessionContextKey contextKey = "session"

// sessionHolder allows the middleware to track session swaps (e.g. Regenerate).
type sessionHolder struct {
	sess *Session
}

const holderContextKey contextKey = "sessionHolder"

// Middleware loads the session on every request, saves it after the handler.
func Middleware(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := store.Load(r)
			if err != nil {
				sess = &Session{
					ID:     generateSID(),
					Data:   make(map[string]any),
					MaxAge: AnonMaxAge,
					dirty:  true,
					isNew:  true,
				}
			}

			holder := &sessionHolder{sess: sess}
			ctx := context.WithValue(r.Context(), sessionContextKey, sess)
			ctx = context.WithValue(ctx, holderContextKey, holder)
			r = r.WithContext(ctx)

			// Capture response with wrapper to save session before first write
			rw := &deferredSaveWriter{
				ResponseWriter: w,
				holder:         holder,
				store:          store,
				request:        r,
				saved:          false,
			}

			next.ServeHTTP(rw, r)

			// Save if handler didn't write anything (e.g. SSE, or empty response)
			if !rw.saved {
				store.Save(w, r, holder.sess)
			}
		})
	}
}

// deferredSaveWriter saves the session to DB and sets the cookie before the first write.
type deferredSaveWriter struct {
	http.ResponseWriter
	holder  *sessionHolder
	store   *Store
	request *http.Request
	saved   bool
}

func (w *deferredSaveWriter) saveOnce() {
	if w.saved {
		return
	}
	w.saved = true
	w.store.Save(w.ResponseWriter, w.request, w.holder.sess)
}

func (w *deferredSaveWriter) WriteHeader(code int) {
	w.saveOnce()
	w.ResponseWriter.WriteHeader(code)
}

func (w *deferredSaveWriter) Write(b []byte) (int, error) {
	w.saveOnce()
	return w.ResponseWriter.Write(b)
}

func (w *deferredSaveWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Flush ensures the session is saved before flushing headers to the client.
// Without this, code that type-asserts to http.Flusher (e.g. SSE handlers)
// would flush response headers before the session cookie is set, potentially
// causing the browser to miss a Set-Cookie header on concurrent responses.
func (w *deferredSaveWriter) Flush() {
	w.saveOnce()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// GetSession retrieves the session from the request context.
func GetSession(r *http.Request) *Session {
	sess, _ := r.Context().Value(sessionContextKey).(*Session)
	return sess
}

// SetSession swaps the session in the holder so the middleware saves the right one.
func SetSession(r *http.Request, sess *Session) {
	if holder, ok := r.Context().Value(holderContextKey).(*sessionHolder); ok {
		holder.sess = sess
	}
}
