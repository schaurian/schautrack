package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"schautrack/internal/service"
	"schautrack/internal/session"
)

func verifyPassword(hash, password string) (bool, error) {
	if hash == "" || password == "" {
		return false, nil
	}
	if strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2a$") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil, nil
	}
	// Argon2 format: $argon2id$...
	return argon2id.ComparePasswordAndHash(password, hash)
}

func hashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func migratePasswordHash(pool *pgxpool.Pool, userID int, password string) {
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

func verifyAndUseBackupCodeForLogin(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
	return verifyAndMarkBackupCode(r, pool, userID, code)
}

// verifyAndMarkBackupCode atomically verifies a backup code and marks it used.
// It reads all unused codes, finds a match in-memory, then uses an atomic UPDATE
// with a WHERE used = FALSE condition to prevent race conditions.
func verifyAndMarkBackupCode(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
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

func replyWithCaptchaIfNeeded(w http.ResponseWriter, sess *session.Session) {
	attempts, _ := sess.GetInt("loginFailedAttempts")
	resp := map[string]any{"ok": false, "error": "Invalid credentials."}
	if attempts >= 3 {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		resp["captchaSvg"] = c.Data
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
		err := h.Pool.QueryRow(r.Context(),
			"SELECT id, password_hash, totp_enabled FROM users WHERE email = $1", emailClean,
		).Scan(&userID, &passwordHash, &totpEnabled)
		if err != nil {
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

		h.Email.Send2FAResetEmail(emailClean, code)
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
	JSON(w, http.StatusOK, map[string]any{"svg": c.Data})
}
