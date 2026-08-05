import { api } from './client';

export interface ApiToken {
  id: number;
  name: string;
  /** Non-secret leading fragment, e.g. "stk_a1b2c3" — enough to tell tokens apart. */
  prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface ScopeInfo {
  scope: string;
  description: string;
}

export interface TokenListResponse {
  ok: boolean;
  tokens: ApiToken[];
  /**
   * The grantable scopes, served by the API rather than hardcoded here. A
   * scope added on the server appears in the UI without a client release, and
   * the checkbox list can never offer one the server would reject.
   */
  scopes: ScopeInfo[];
  max: number;
}

export interface CreatedToken {
  ok: boolean;
  /** The raw secret. Returned once, at creation, and never retrievable again. */
  token: string;
  record: ApiToken;
}

export function listApiTokens() {
  return api<TokenListResponse>('/api/tokens');
}

export function createApiToken(name: string, scopes: string[], expiresInDays?: number) {
  return api<CreatedToken>('/api/tokens', {
    method: 'POST',
    body: JSON.stringify({
      name,
      scopes,
      expires_in_days: expiresInDays ?? null,
    }),
  });
}

export function revokeApiToken(id: number) {
  return api<{ ok: boolean }>(`/api/tokens/${id}/delete`, { method: 'POST' });
}
