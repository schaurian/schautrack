package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"schautrack/internal/service"
	"schautrack/internal/session"
)

// derefLang safely dereferences a user's *string language field, e.g.
// model.User.Language, returning "" (which renderEmail/normalizeEmailLang
// treats as "fall back to en") when the pointer is nil.
func derefLang(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// argon2Compare is the argon2id verification every password check goes
// through. It is a variable solely so tests can observe what reaches the KDF:
// "argon2id is never handed an unbounded client-supplied string" (issue #340)
// is a property of the *argument*, and there is no other way to assert it
// without measuring wall-clock time. Production code must never reassign it.
var argon2Compare = argon2id.ComparePasswordAndHash

// verifyPassword reports whether password matches hash, supporting both the
// current argon2id format and legacy bcrypt hashes.
//
// This is the single choke point for every path that checks a password
// against a stored hash — login, the 2FA-reset request, and step-up
// re-authentication — which is why the length bound lives here rather than at
// the three call sites: a verification path added later inherits it.
func verifyPassword(hash, password string) (bool, error) {
	if hash == "" || password == "" {
		return false, nil
	}
	if passwordExceedsVerifyCap(password) {
		// Over the cost bound: the submitted string must not reach argon2id.
		// Burn the standard verification cost against the dummy hash instead,
		// so this is indistinguishable from a wrong password in both the
		// response the caller writes and the time it takes to get there.
		// Returning early *without* the burn would turn "is this email
		// registered?" into a stopwatch question — the unknown-email path
		// pays the same cost via equalizeLoginTiming.
		slog.Warn("rejected over-long password at a verification path",
			"bytes", len(password), "limit", MaxVerifyPasswordBytes)
		burnPasswordVerifyCost(oversizedPasswordStandIn)
		return false, nil
	}
	if strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2a$") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil, nil
	}
	// Argon2 format: $argon2id$...
	return argon2Compare(password, hash)
}

func hashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

// maxBackupCodeBytes bounds the backup code a client may submit. A generated
// code is 8 digits; the slack is for a pasted value carrying separators or
// surrounding whitespace, so a user's formatting mistake still fails on the
// comparison rather than on an invisible length rule.
const maxBackupCodeBytes = 64

// bcryptMaxBytes is how much of a password bcrypt actually consumes. Its
// blowfish key schedule reads 18 x 4 = 72 bytes and ignores the rest;
// CompareHashAndPassword neither errors nor costs more for a longer input.
const bcryptMaxBytes = 72

// migratePasswordHash upgrades a legacy bcrypt hash to argon2id after a
// successful login.
//
// It refuses to migrate a password longer than bcrypt validated (#397).
// bcrypt compared only the first 72 bytes, so every string sharing that prefix
// logged in — but argon2id compares the WHOLE string. Re-hashing the submitted
// bytes therefore narrows the account to one specific member of the set that
// used to work, chosen by whoever logged in last:
//
//   - a user whose real password is 80 characters, who has been logging in with
//     a browser that truncates at 72, silently loses the ability to use the
//     other spelling;
//   - worse, anyone who obtained the 72-byte prefix could log in AND, in the
//     same request, rewrite the stored hash to a longer string of their
//     choosing that the real owner does not know.
//
// Skipping the migration leaves the account on bcrypt, which is exactly the
// status quo: no worse than before, and no silent change to what the password
// is. These accounts stay on bcrypt until someone logs in with a password
// bcrypt could fully see, or changes it — both of which go through the normal
// argon2id path.
func migratePasswordHash(pool *pgxpool.Pool, userID int, password string) {
	if len(password) > bcryptMaxBytes {
		slog.Warn("skipping bcrypt->argon2id migration: password exceeds what bcrypt validated",
			"user_id", userID, "bytes", len(password), "bcrypt_limit", bcryptMaxBytes)
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		return
	}
	if _, err := pool.Exec(context.Background(), "UPDATE users SET password_hash = $1 WHERE id = $2", hash, userID); err != nil {
		slog.Error("failed to migrate password hash", "error", err, "user_id", userID)
	}
}

func recordLoginFailure(sess *session.Session) {
	attempts, _ := sess.GetInt("loginFailedAttempts")
	sess.Set("loginFailedAttempts", attempts+1)
}

// maxLogin2FAFailures caps failed TOTP/backup-code attempts during the
// pending-2FA login step, mirroring stepup.go's maxStepUpFailures. Without a
// cap, the 6-digit TOTP is brute-forceable through the bypassable IP limiter.
const maxLogin2FAFailures = 5

// recordLogin2FAFailure increments the pending-login 2FA failure counter and
// reports whether the cap was reached. When it returns true, the pending
// login state has been cleared and the caller must destroy the session and
// reply with a lockout response (mirroring recordStepUpFailure).
func recordLogin2FAFailure(sess *session.Session) bool {
	failures, _ := sess.GetInt("login2faFailures")
	failures++
	sess.Set("login2faFailures", failures)
	if failures >= maxLogin2FAFailures {
		sess.Delete("pendingUserId")
		sess.Delete("login2faFailures")
		return true
	}
	return false
}

// dummyPasswordHash lazily precomputes an argon2id hash (same DefaultParams
// as real user hashes) used to equalize login timing when the email doesn't
// match any account. Without it, unknown emails return after a cheap DB miss
// while known emails pay a slow argon2id verify — a measurable
// user-enumeration timing oracle.
var dummyPasswordHash = sync.OnceValue(func() string {
	hash, err := argon2id.CreateHash("schautrack-timing-equalization-dummy", argon2id.DefaultParams)
	if err != nil {
		// CreateHash only fails if crypto/rand fails; skip equalization
		// rather than crashing logins.
		slog.Error("failed to precompute dummy password hash", "error", err)
		return ""
	}
	return hash
})

// oversizedPasswordStandIn is hashed in place of a client-supplied password
// that exceeds MaxVerifyPasswordBytes. Nothing is compared against it — the
// point is only to pay the argon2id cost with a bounded input, so an
// over-long password costs the server exactly one normal verification instead
// of one verification plus a Blake2b pass over megabytes.
const oversizedPasswordStandIn = "schautrack-oversized-password-stand-in"

// burnPasswordVerifyCost performs one argon2id verification against the
// precomputed dummy hash. Callers use it to spend the cost of a password
// check they are not actually performing.
func burnPasswordVerifyCost(password string) {
	if hash := dummyPasswordHash(); hash != "" {
		_, _ = argon2Compare(password, hash)
	}
}

// equalizeLoginTiming burns the same argon2id verification cost as a real
// password check. Called on the unknown-email login path so its duration is
// indistinguishable from a wrong password on an existing account.
//
// It applies the same MaxVerifyPasswordBytes bound as verifyPassword, and it
// must: this is the branch an attacker reaches by inventing an email address,
// so it is the *cheapest* way to make the server hash a multi-megabyte string
// — no account required. Bounding only verifyPassword would also have made
// the two branches diverge in duration for an over-long password, handing
// back the account-existence oracle this function exists to close.
func equalizeLoginTiming(password string) {
	if passwordExceedsVerifyCap(password) {
		password = oversizedPasswordStandIn
	}
	burnPasswordVerifyCost(password)
}

func verifyAndUseBackupCodeForLogin(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
	return verifyAndMarkBackupCode(r, pool, userID, code)
}

// verifyAndMarkBackupCode atomically verifies a backup code and marks it used.
// It reads all unused codes, finds a match in-memory, then uses an atomic UPDATE
// with a WHERE used = FALSE condition to prevent race conditions.
func verifyAndMarkBackupCode(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
	// Bound the client string before it reaches the hash loop (#404).
	//
	// VerifyBackupCode re-hashes `code` once per unused code, so with
	// service.BackupCodeCount stored codes an unbounded token is that many
	// SHA-256 passes over whatever the client sent. Only ReadJSON's 10 MB body
	// limit stood in the way: a 10 MB token cost roughly a quarter second of
	// CPU per request, unauthenticated at the login 2FA step.
	//
	// A real code is 8 digits (service.GenerateBackupCodes), so anything longer
	// than this cannot match any stored hash — the check costs nothing and
	// rejects exactly the inputs that were only ever going to fail. The bound
	// is loose rather than exactly 8 so that a formatted paste ("1234-5678",
	// surrounding spaces) still reaches the comparison and fails on its own
	// merits rather than on a length rule the user cannot see.
	if len(code) > maxBackupCodeBytes {
		slog.Warn("rejected an over-long backup code before hashing",
			"user_id", userID, "bytes", len(code), "limit", maxBackupCodeBytes)
		return false
	}

	rows, err := pool.Query(r.Context(),
		"SELECT id, code_hash FROM totp_backup_codes WHERE user_id = $1 AND used = FALSE", userID)
	if err != nil {
		return false
	}
	defer rows.Close()

	// Collect all codes first, then close the result set before updating
	type codeEntry struct {
		id   int
		hash string
	}
	var codes []codeEntry
	for rows.Next() {
		var c codeEntry
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			continue
		}
		codes = append(codes, c)
	}
	rows.Close()

	for _, c := range codes {
		if service.VerifyBackupCode(code, c.hash) {
			// Atomic: only marks used if still unused (prevents race condition)
			tag, err := pool.Exec(r.Context(),
				"UPDATE totp_backup_codes SET used = TRUE WHERE id = $1 AND used = FALSE", c.id)
			if err != nil || tag.RowsAffected() == 0 {
				return false // Already used by a concurrent request
			}
			return true
		}
	}
	return false
}

func replyWithCaptchaIfNeeded(w http.ResponseWriter, sess *session.Session, email, ip string) {
	resp := map[string]any{"ok": false, "error": "Invalid credentials."}
	if loginCaptchaRequired(sess, email, ip) {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		resp["captchaSvg"] = c.Data
		resp["captchaQuestion"] = c.Question
		resp["requireCaptcha"] = true
	}
	JSON(w, http.StatusUnauthorized, resp)
}

// Reset2FA handles POST /api/auth/reset-2fa
// Allows a user who is stuck at the 2FA login step to disable 2FA via email verification.
func (h *AuthHandler) Reset2FA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Step     string `json:"step"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if !h.Email.IsConfigured() {
		ErrorJSON(w, http.StatusBadRequest, "Email is not configured on this server.")
		return
	}

	sess := session.GetSession(r)

	switch body.Step {
	case "request":
		emailClean := strings.ToLower(strings.TrimSpace(body.Email))
		if emailClean == "" || body.Password == "" {
			ErrorJSON(w, http.StatusBadRequest, "Email and password are required.")
			return
		}

		var userID int
		var passwordHash string
		var totpEnabled bool
		var userLanguage *string
		err := h.Pool.QueryRow(r.Context(),
			"SELECT id, password_hash, totp_enabled, language FROM users WHERE email = $1", emailClean,
		).Scan(&userID, &passwordHash, &totpEnabled, &userLanguage)
		if err != nil {
			// Pay the verification cost we are skipping (#401).
			//
			// An unknown address returned here after a cheap index miss, while
			// a known one went on to spend a full argon2id verification below.
			// The bodies were identical and the durations were not, so a
			// stopwatch answered "is this address registered?" — to an
			// UNAUTHENTICATED caller, which is what makes this worse than the
			// same shape on an authenticated route.
			//
			// Login already equalizes its own unknown-email path this way; this
			// endpoint takes the same email and password and simply forgot to.
			equalizeLoginTiming(body.Password)
			ErrorJSON(w, http.StatusUnauthorized, "Invalid credentials.")
			return
		}

		valid, _ := verifyPassword(passwordHash, body.Password)
		if !valid {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid credentials.")
			return
		}

		if !totpEnabled {
			ErrorJSON(w, http.StatusBadRequest, "2FA is not enabled on this account.")
			return
		}

		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(15*time.Minute)); err != nil {
			slog.Error("failed to insert 2FA reset token", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not send reset code.")
			return
		}

		if err := h.Email.Send2FAResetEmail(emailClean, code, derefLang(userLanguage)); err != nil {
			// Caller already proved email+password, so surfacing the send
			// failure reveals nothing about account existence.
			ErrorJSON(w, http.StatusInternalServerError, "Could not send reset code. Please try again.")
			return
		}
		sess.Set("reset2faUserId", userID)
		sess.Set("reset2faAttempts", 0)
		OkJSON(w)

	case "verify":
		userID, ok := sess.GetInt("reset2faUserId")
		if !ok || userID == 0 {
			ErrorJSON(w, http.StatusBadRequest, "No 2FA reset session.")
			return
		}

		attempts, _ := sess.GetInt("reset2faAttempts")
		if attempts >= 5 {
			sess.Delete("reset2faUserId")
			sess.Delete("reset2faAttempts")
			ErrorJSON(w, http.StatusTooManyRequests, "Too many attempts. Please start over.")
			return
		}
		sess.Set("reset2faAttempts", attempts+1)

		code := strings.TrimSpace(body.Code)
		if code == "" {
			ErrorJSON(w, http.StatusBadRequest, "Code is required.")
			return
		}

		var tokenID int
		var expiresAt time.Time
		err := h.Pool.QueryRow(r.Context(), `
			SELECT id, expires_at FROM password_reset_tokens
			WHERE user_id = $1 AND token = $2 AND used = FALSE
			ORDER BY created_at DESC LIMIT 1`,
			userID, code).Scan(&tokenID, &expiresAt)
		if err != nil || time.Now().After(expiresAt) {
			ErrorJSON(w, http.StatusBadRequest, "Invalid or expired code.")
			return
		}

		// Disable 2FA in a transaction
		tx, txErr := h.Pool.Begin(r.Context())
		if txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}
		defer tx.Rollback(r.Context())

		if _, txErr = tx.Exec(r.Context(), "UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1", userID); txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}
		if _, txErr = tx.Exec(r.Context(), "DELETE FROM totp_backup_codes WHERE user_id = $1", userID); txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}
		if _, txErr = tx.Exec(r.Context(), "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1", tokenID); txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}
		// Removing 2FA is a credential change: kill every existing session
		// for the account so a stolen cookie doesn't survive the reset. The
		// caller is on an anonymous session (login page), which has no
		// userId and is therefore unaffected.
		if txErr = invalidateUserSessions(r.Context(), tx, userID, ""); txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}
		if txErr = tx.Commit(r.Context()); txErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not reset 2FA.")
			return
		}

		sess.Delete("reset2faUserId")
		sess.Delete("reset2faAttempts")
		sess.Delete("pendingUserId")
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "2FA removed. You can now log in with your password."})

	default:
		ErrorJSON(w, http.StatusBadRequest, "Invalid step.")
	}
}

// Captcha handles GET /api/auth/captcha
func (h *AuthHandler) Captcha(w http.ResponseWriter, r *http.Request) {
	c := service.GenerateCaptcha()
	sess := session.GetSession(r)
	sess.Set("captchaAnswer", c.Text)
	JSON(w, http.StatusOK, map[string]any{"svg": c.Data, "question": c.Question})
}
