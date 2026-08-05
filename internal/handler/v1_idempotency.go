package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
)

// slogWarn logs a non-fatal problem in the idempotency bookkeeping. These are
// deliberately warnings: the client already has its response, and the worst
// consequence is that a retry re-executes, which is the pre-existing behaviour.
func slogWarn(msg string, err error) { slog.Warn(msg, "error", err) }

// Idempotency-Key support for the public API's create endpoints.
//
// PUT endpoints (weight, notes, todo completions) are idempotent by
// construction: the URL names the resource and the body states the desired
// state, so a retry is a no-op. POST is not. A script that logs a meal, times
// out waiting for the response, and retries has no safe option — retrying may
// double-log, and not retrying may lose the meal entirely.
//
// The client breaks the tie by sending a key it generates once per logical
// operation and reuses across retries. The first request executes and its
// response is stored; every retry with that key replays the stored response
// instead of creating a second entry.

const (
	// idempotencyHeader is the de facto standard name, and the one the IETF
	// draft (draft-ietf-httpapi-idempotency-key-header) settled on.
	idempotencyHeader = "Idempotency-Key"

	// idempotencyTTL is how long a key is remembered. Long enough to cover any
	// plausible retry (including a phone that reconnects hours later), short
	// enough that the table does not grow without bound.
	idempotencyTTL = 24 * time.Hour

	maxIdempotencyKeyLen = 255
)

// recorder captures a handler's response so it can be stored and replayed.
type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (rec *recorder) WriteHeader(status int) {
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	rec.body.Write(b)
	return rec.ResponseWriter.Write(b)
}

// withIdempotency wraps a create handler so that repeating a request with the
// same Idempotency-Key replays the original response instead of acting again.
//
// With no header the handler runs exactly as before — the feature is opt-in, so
// it cannot break a client that has never heard of it.
func (h *V1Handler) withIdempotency(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(idempotencyHeader)
		if key == "" {
			next(w, r)
			return
		}
		if len(key) > maxIdempotencyKeyLen {
			apierr.Write(w, r, apierr.BadRequest(
				"The Idempotency-Key header is too long (maximum 255 characters)."))
			return
		}

		// The body is needed twice: once to fingerprint the request, once by
		// the handler. Buffer it and hand the handler a fresh reader.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxV1Body))
		if err != nil {
			apierr.Write(w, r, apierr.BadRequest("The request body could not be read."))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		fingerprint := fingerprintRequest(r, body)
		user := v1User(r)

		// Claim the key before doing any work. INSERT ... ON CONFLICT DO
		// NOTHING is atomic, so of two concurrent retries exactly one claims
		// it and the other observes the claim — neither can execute twice.
		var claimed bool
		if err := h.Pool.QueryRow(r.Context(), `
			INSERT INTO api_idempotency (user_id, idempotency_key, request_fingerprint)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, idempotency_key) DO NOTHING
			RETURNING true`, user.ID, key, fingerprint,
		).Scan(&claimed); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			apierr.Write(w, r, dbFail("claim idempotency key", err))
			return
		}

		if !claimed {
			h.replayIdempotent(w, r, user.ID, key, fingerprint)
			return
		}

		rec := &recorder{ResponseWriter: w}
		next(rec, r)

		// Only successful creates are worth replaying. A failed request should
		// be retryable normally — storing a 422 would pin the client to an
		// error it may have already fixed. Releasing the claim lets the retry
		// through.
		if rec.status < 200 || rec.status > 299 {
			if _, err := h.Pool.Exec(r.Context(),
				`DELETE FROM api_idempotency WHERE user_id = $1 AND idempotency_key = $2`,
				user.ID, key); err != nil {
				slogWarn("failed to release idempotency claim after an error response", err)
			}
			return
		}

		if _, err := h.Pool.Exec(r.Context(), `
			UPDATE api_idempotency
			SET response_status = $3, response_body = $4, response_location = $5
			WHERE user_id = $1 AND idempotency_key = $2`,
			user.ID, key, rec.status, rec.body.Bytes(), w.Header().Get("Location"),
		); err != nil {
			// The response has already gone out, so this cannot be turned into
			// an error. Worst case the client's retry re-executes, which is the
			// behaviour it had before this feature existed.
			slogWarn("failed to store idempotent response", err)
		}
	}
}

// replayIdempotent answers a request whose key was already claimed.
func (h *V1Handler) replayIdempotent(w http.ResponseWriter, r *http.Request, userID int, key string, fingerprint []byte) {
	var status int
	var storedFingerprint, storedBody []byte
	var location *string
	var createdAt time.Time

	err := h.Pool.QueryRow(r.Context(), `
		SELECT response_status, request_fingerprint, response_body, response_location, created_at
		FROM api_idempotency WHERE user_id = $1 AND idempotency_key = $2`,
		userID, key,
	).Scan(&status, &storedFingerprint, &storedBody, &location, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The claim was released between the failed insert and this read —
			// the original request errored. Tell the client to try again.
			apierr.Write(w, r, apierr.Conflict(
				"A request with this Idempotency-Key was in flight and did not complete. Retry it."))
			return
		}
		apierr.Write(w, r, dbFail("read idempotency record", err))
		return
	}

	// Same key, different request. Replaying would silently discard what the
	// client just asked for, so say so instead.
	if !bytes.Equal(storedFingerprint, fingerprint) {
		apierr.Write(w, r, apierr.Conflict(
			"This Idempotency-Key was already used for a different request. Use a new key."))
		return
	}

	if status == 0 {
		// Claimed but not yet finished — the original is still running.
		apierr.Write(w, r, apierr.Conflict(
			"A request with this Idempotency-Key is still in progress. Retry shortly."))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Idempotency-Replayed", "true")
	if location != nil && *location != "" {
		w.Header().Set("Location", *location)
	}
	w.WriteHeader(status)
	w.Write(storedBody)
}

// fingerprintRequest digests what makes a request distinct, so a recycled key
// can be told apart from a genuine retry.
func fingerprintRequest(r *http.Request, body []byte) []byte {
	sum := sha256.New()
	sum.Write([]byte(r.Method))
	sum.Write([]byte{0})
	sum.Write([]byte(r.URL.Path))
	sum.Write([]byte{0})
	sum.Write(body)
	return sum.Sum(nil)
}

// CleanExpiredIdempotencyKeys drops replay records past their TTL. Called from
// the server's periodic cleanup loop alongside the expired-token sweep.
func CleanExpiredIdempotencyKeys(pool *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx,
		`DELETE FROM api_idempotency WHERE created_at < NOW() - $1::interval`,
		idempotencyTTL.String()); err != nil {
		slogWarn("failed to prune expired idempotency keys", err)
	}
}
