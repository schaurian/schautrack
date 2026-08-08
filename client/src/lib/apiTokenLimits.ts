import type { ApiToken } from '@/api/apiTokens';

/**
 * Which API tokens are dead, and which ones count against the per-user limit.
 *
 * This lives apart from the settings card because the rule has to match the
 * server's exactly: `CreateAPIToken` caps *active* tokens (unrevoked and
 * unexpired), while the list endpoint deliberately returns expired ones too so
 * the user can see and clear them. Gating the "New token" button on the raw
 * list length told a user with 20 tokens — 8 of them lapsed — that they were at
 * the limit, and hid the button entirely, while the server would have minted
 * eight more (issue #299).
 */

/** The fields the expiry rule reads. */
type TokenExpiry = Pick<ApiToken, 'expires_at' | 'expired'>;

/**
 * Whether a token has lapsed.
 *
 * Prefers the server's `expired` flag: the limit is enforced against the
 * server's clock, so anything the UI decides from a browser clock could
 * disagree with it — which is the class of bug this module exists to prevent.
 * The `expires_at` comparison is only a fallback for a response that predates
 * the flag (possible mid-rollout, when a new bundle can hit an old pod).
 */
export function isTokenExpired(token: TokenExpiry, now: Date = new Date()): boolean {
  if (typeof token.expired === 'boolean') return token.expired;
  if (!token.expires_at) return false;
  return new Date(token.expires_at).getTime() <= now.getTime();
}

/** How many of these tokens count against the limit. */
export function activeTokenCount(tokens: TokenExpiry[], now?: Date): number {
  return tokens.reduce((n, token) => (isTokenExpired(token, now) ? n : n + 1), 0);
}

/**
 * Whether the user may still mint a token. Counts the active subset only, so it
 * agrees with the server's cap.
 */
export function isAtTokenLimit(tokens: TokenExpiry[], max: number, now?: Date): boolean {
  return activeTokenCount(tokens, now) >= max;
}
