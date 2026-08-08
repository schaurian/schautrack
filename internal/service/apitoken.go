package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/model"
)

// --- Scopes ---------------------------------------------------------------

// Scope constants. The naming is resource:action; a ":write" scope implies the
// matching ":read" (see ScopeSatisfies), which is what callers expect and what
// keeps token-minting UIs from having to explain why "write" alone 403s on a
// GET.
const (
	ScopeEntriesRead   = "entries:read"
	ScopeEntriesWrite  = "entries:write"
	ScopeWeightRead    = "weight:read"
	ScopeWeightWrite   = "weight:write"
	ScopeTodosRead     = "todos:read"
	ScopeTodosWrite    = "todos:write"
	ScopeFoodsRead     = "foods:read"
	ScopeFoodsWrite    = "foods:write"
	ScopeNotesRead     = "notes:read"
	ScopeNotesWrite    = "notes:write"
	ScopePlanRead      = "plan:read"
	ScopeLinksRead     = "links:read"
	ScopeSettingsRead  = "settings:read"
	ScopeSettingsWrite = "settings:write"

	// ScopeAIEstimate is deliberately its own scope, implied by nothing.
	//
	// Every request to it spends real money on the operator's AI provider. If
	// it rode along with entries:write — the scope any meal-logging script
	// needs — a token minted for "log my breakfast" could quietly run up an
	// OpenAI bill. Granting it has to be a separate, conscious act.
	ScopeAIEstimate = "ai:estimate"
)

// ScopeDescriptions is the closed set of grantable scopes, in the order the
// token UI and the generated documentation present them. Anything absent here
// is rejected by ValidateScopes, so a typo at mint time fails loudly instead of
// silently producing a token that can never authorize anything.
var ScopeDescriptions = []struct{ Scope, Description string }{
	{ScopeEntriesRead, "Read calorie entries and their macros."},
	{ScopeEntriesWrite, "Create, update, and delete calorie entries."},
	{ScopeWeightRead, "Read weight entries."},
	{ScopeWeightWrite, "Record and delete weight entries."},
	{ScopeTodosRead, "Read todos and their completion state."},
	{ScopeTodosWrite, "Create, update, delete, and complete todos."},
	{ScopeFoodsRead, "Read saved foods."},
	{ScopeFoodsWrite, "Create, update, and delete saved foods."},
	{ScopeNotesRead, "Read daily notes."},
	{ScopeNotesWrite, "Write daily notes."},
	{ScopePlanRead, "Read the weight-loss plan, its goal, and its projections."},
	{ScopeLinksRead, "Read data that linked accounts have shared with you."},
	{ScopeSettingsRead, "Read account settings (goal, timezone, units, language)."},
	{ScopeSettingsWrite, "Change account settings (goal, timezone, units, language)."},
	{ScopeAIEstimate, "Estimate nutrition from a food photo. Costs money per call — grant sparingly."},
}

// AllScopes returns every grantable scope.
func AllScopes() []string {
	out := make([]string, 0, len(ScopeDescriptions))
	for _, s := range ScopeDescriptions {
		out = append(out, s.Scope)
	}
	return out
}

func isKnownScope(s string) bool {
	for _, d := range ScopeDescriptions {
		if d.Scope == s {
			return true
		}
	}
	return false
}

// ErrNoScopes is returned when a token is requested with an empty scope set. A
// scopeless token could authenticate but authorize nothing, which is a trap
// rather than a feature.
var ErrNoScopes = errors.New("at least one scope is required")

// ValidateScopes normalizes a requested scope set: it trims, lowercases,
// de-duplicates, sorts, and rejects anything not in ScopeDescriptions. Sorting
// makes the stored value canonical, so two tokens minted with the same scopes
// in different orders compare equal.
func ValidateScopes(requested []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range requested {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if !isKnownScope(s) {
			return nil, fmt.Errorf("unknown scope %q", s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, ErrNoScopes
	}
	sort.Strings(out)
	return out, nil
}

// ScopeSatisfies reports whether a granted scope set authorizes required.
//
// A ":write" scope satisfies the matching ":read" — holding entries:write but
// not entries:read still lets you GET entries. The converse never holds.
func ScopeSatisfies(granted []string, required string) bool {
	var implied string
	if resource, ok := strings.CutSuffix(required, ":read"); ok {
		implied = resource + ":write"
	}
	for _, g := range granted {
		if g == required || (implied != "" && g == implied) {
			return true
		}
	}
	return false
}

// --- Token generation -----------------------------------------------------

const (
	// TokenPrefix marks Schautrack tokens in logs, secret scanners, and .env
	// files. A distinctive prefix is what makes automated leak detection
	// (GitHub secret scanning and friends) possible at all.
	TokenPrefix = "stk_"

	// tokenEntropyBytes is the size of the random secret. 32 bytes = 256 bits,
	// far past any brute-force concern, which is why the digest below can be a
	// plain fast hash instead of a password KDF.
	tokenEntropyBytes = 32

	// prefixDisplayLen is how many secret characters are stored in the clear
	// for display. Six characters of base64 is 36 bits — enough to tell tokens
	// apart in a list, nowhere near enough to guess the remaining 220.
	prefixDisplayLen = 6

	// MaxTokensPerUser caps active tokens so a runaway script cannot mint
	// unbounded rows.
	MaxTokensPerUser = 20

	// MaxTokenNameLen bounds the user-supplied label.
	MaxTokenNameLen = 60
)

// GenerateAPIToken returns a new raw token and its storage digest.
//
// The digest is a bare SHA-256, deliberately, not argon2id. Argon2 exists to
// make low-entropy human passwords expensive to guess; this secret is 256
// uniform random bits, so there is nothing to slow down. Using a KDF here
// would only add ~50ms of CPU to every single authenticated API request.
func GenerateAPIToken() (raw string, digest []byte, prefix string, err error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, "", fmt.Errorf("generate token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	raw = TokenPrefix + secret
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], TokenPrefix + secret[:prefixDisplayLen], nil
}

// HashAPIToken returns the storage digest for a raw token.
func HashAPIToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// ParseBearer extracts a token from an Authorization header value. It requires
// the "Bearer" scheme (case-insensitively, per RFC 7235) and returns "" for
// anything else, including Basic auth and a bare token with no scheme.
func ParseBearer(header string) string {
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// LooksLikeAPIToken reports whether s has the Schautrack token shape. Used to
// reject obvious non-tokens before hitting the database.
func LooksLikeAPIToken(s string) bool {
	return strings.HasPrefix(s, TokenPrefix) && len(s) > len(TokenPrefix)+prefixDisplayLen
}

// --- Persistence ----------------------------------------------------------

// ErrTokenLimit is returned when a user already holds MaxTokensPerUser active
// tokens.
var ErrTokenLimit = fmt.Errorf("token limit reached (maximum %d)", MaxTokensPerUser)

// activeTokenCountSQL is the single definition of "counts against
// MaxTokensPerUser": unrevoked and unexpired, judged by the database clock.
//
// It is shared rather than copied because the copies drifted once already.
// ListAPITokens keeps expired tokens, this count ignores them, and the token UI
// gated its "New token" button on the raw list length — so a user holding 20
// tokens of which 8 had lapsed was told they were at the limit while the server
// would happily have minted eight more, with no way out of the UI except
// revoking dead tokens one at a time (issue #299). Anything answering "is this
// user at the limit?" must go through here.
const activeTokenCountSQL = `
	SELECT COUNT(*)::int FROM api_tokens
	WHERE user_id = $1 AND revoked_at IS NULL
	  AND (expires_at IS NULL OR expires_at > NOW())`

// CountActiveAPITokens returns how many of a user's tokens count against
// MaxTokensPerUser.
//
// It takes a Querier so the mint path can run it inside its transaction while
// callers outside one pass the pool.
func CountActiveAPITokens(ctx context.Context, db Querier, userID int) (int, error) {
	var n int
	if err := db.QueryRow(ctx, activeTokenCountSQL, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CreateAPIToken mints a token for a user and returns it along with the raw
// secret. The raw secret is the only copy — it is never recoverable again.
func CreateAPIToken(ctx context.Context, pool *pgxpool.Pool, userID int, name string, scopes []string, expiresAt *time.Time) (*model.APIToken, string, error) {
	scopes, err := ValidateScopes(scopes)
	if err != nil {
		return nil, "", err
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", errors.New("name is required")
	}
	if len([]rune(name)) > MaxTokenNameLen {
		name = string([]rune(name)[:MaxTokenNameLen])
	}

	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return nil, "", errors.New("expires_at must be in the future")
	}

	// Count and insert in one transaction so two concurrent mints cannot both
	// observe count = MaxTokensPerUser-1 and both succeed.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	active, err := CountActiveAPITokens(ctx, tx, userID)
	if err != nil {
		return nil, "", err
	}
	if active >= MaxTokensPerUser {
		return nil, "", ErrTokenLimit
	}

	raw, digest, prefix, err := GenerateAPIToken()
	if err != nil {
		return nil, "", err
	}

	t := &model.APIToken{UserID: userID, Name: name, Prefix: prefix, Scopes: scopes, ExpiresAt: expiresAt}
	if err := tx.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`,
		userID, name, digest, prefix, scopes, expiresAt,
	).Scan(&t.ID, &t.CreatedAt); err != nil {
		return nil, "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return t, raw, nil
}

// ListAPITokens returns a user's tokens, newest first. Revoked tokens are
// excluded: they are dead weight in a management UI, and the row is retained
// only so the digest stays burned.
//
// Expired tokens ARE returned, deliberately. A token that quietly lapsed is the
// likeliest explanation for "my script started getting 401s", so dropping it
// from the list would delete the only place the user could discover that, and
// leave them no way to tidy the row away either.
//
// The consequence: len(the returned slice) is NOT the number of tokens that
// count against MaxTokensPerUser. Callers deciding whether a user may mint
// another must use CountActiveAPITokens or filter on model.APIToken.Active —
// counting the raw list is exactly the bug in issue #299. The handler stamps
// each row with an Expired flag so the UI can gate on the active subset (and
// grey the dead ones out) without trusting the browser clock.
func ListAPITokens(ctx context.Context, pool *pgxpool.Pool, userID int) ([]model.APIToken, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, prefix, scopes, expires_at, last_used_at, created_at, revoked_at
		FROM api_tokens
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := []model.APIToken{}
	for rows.Next() {
		var t model.APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Scopes,
			&t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		t.UserID = userID
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RevokeAPIToken marks a token revoked. It reports whether a row was affected,
// so the caller can 404 on an id that is not this user's.
//
// The row is kept rather than deleted: the unique index on token_hash then
// guarantees the same secret can never be resurrected, and last_used_at stays
// available for after-the-fact "was this leaked token used?" questions.
func RevokeAPIToken(ctx context.Context, pool *pgxpool.Pool, userID, tokenID int) (bool, error) {
	tag, err := pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = NOW()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, tokenID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ErrTokenInvalid is returned by AuthenticateAPIToken for every rejection
// reason — unknown, revoked, or expired.
//
// The reasons are deliberately not distinguished in the returned error: a
// caller that could tell "revoked" from "unknown" apart would have an oracle
// for probing which token strings ever existed.
var ErrTokenInvalid = errors.New("invalid api token")

// AuthenticateAPIToken resolves a raw token to its record. It returns
// ErrTokenInvalid unless the token exists, is unrevoked, and is unexpired.
func AuthenticateAPIToken(ctx context.Context, pool *pgxpool.Pool, raw string) (*model.APIToken, error) {
	if !LooksLikeAPIToken(raw) {
		return nil, ErrTokenInvalid
	}
	digest := HashAPIToken(raw)

	var t model.APIToken
	var storedHash []byte
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, name, token_hash, prefix, scopes, expires_at, last_used_at, created_at, revoked_at
		FROM api_tokens WHERE token_hash = $1`, digest,
	).Scan(&t.ID, &t.UserID, &t.Name, &storedHash, &t.Prefix, &t.Scopes,
		&t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt, &t.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenInvalid
		}
		return nil, err
	}

	// The lookup already matched on an indexed equality, so this comparison is
	// belt-and-braces — but it is the one comparison of secret material in the
	// path, so it is constant-time on principle.
	if subtle.ConstantTimeCompare(storedHash, digest) != 1 {
		return nil, ErrTokenInvalid
	}
	if !t.Active(time.Now()) {
		return nil, ErrTokenInvalid
	}
	return &t, nil
}

// TouchLastUsedInterval is the coarseness of last_used_at. Writing on every
// request would turn each read-only API call into a write and contend on the
// row; a minute is plenty for "when was this token last active?".
const TouchLastUsedInterval = time.Minute

// TouchAPIToken refreshes last_used_at if it is stale. The WHERE clause does
// the staleness check in SQL so concurrent requests cannot both decide to
// write.
func TouchAPIToken(ctx context.Context, pool *pgxpool.Pool, tokenID int) error {
	_, err := pool.Exec(ctx, `
		UPDATE api_tokens SET last_used_at = NOW()
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < NOW() - $2::interval)`,
		tokenID, TouchLastUsedInterval.String())
	return err
}
