/**
 * bcrypt hashing for the E2E database seeds.
 *
 * New passwords are stored as argon2id, but the app still *verifies* legacy bcrypt
 * hashes and transparently migrates them on the next successful login — see
 * `verifyPassword` / `migratePasswordHash` in `internal/handler/auth_helpers.go`.
 * Several specs seed a bcrypt hash straight into the `users` table to exercise that
 * path, so the suite has to be able to mint one.
 *
 * This used to shell out to `python3 -c "import bcrypt; ..."`, an undocumented host
 * prerequisite that `npm ci` could not satisfy and whose failure mode was an opaque
 * subprocess error before a single spec ran. `bcryptjs` is pure JavaScript with no
 * native build step, so `npm ci` is now enough — and the password is passed as a
 * value, so one containing a quote or a backslash can no longer break the command.
 *
 * Hash compatibility: `verifyPassword` only routes `$2a$`/`$2b$` prefixes to
 * `golang.org/x/crypto/bcrypt`; bcryptjs emits `$2b$`, which that verifier accepts.
 */
import bcrypt from 'bcryptjs';

/**
 * bcrypt cost factor. Matches the cost the old Node.js backend wrote, which is what
 * the migration specs are meant to be reproducing. Keep it low — this runs once per
 * seeded user and every extra round doubles the time.
 */
const BCRYPT_COST = 10;

/** Generate a bcrypt hash for the given password. */
export function bcryptHash(password: string): string {
  return bcrypt.hashSync(password, BCRYPT_COST);
}
