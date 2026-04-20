import { api } from './client';

export function passkeyLoginBegin() {
  return api<PublicKeyCredentialRequestOptionsJSON>('/passkeys/login/begin', { method: 'POST' });
}

export function passkeyLoginFinish(credential: AuthenticatorAssertionResponseJSON) {
  return api<{ ok: boolean }>('/passkeys/login/finish', {
    method: 'POST',
    body: JSON.stringify(credential),
  });
}

export function passkeyRegisterBegin() {
  return api<PublicKeyCredentialCreationOptionsJSON>('/passkeys/register/begin', { method: 'POST' });
}

export function passkeyRegisterFinish(credential: AuthenticatorAttestationResponseJSON, name: string) {
  return api<{ ok: boolean }>(`/passkeys/register/finish?name=${encodeURIComponent(name)}`, {
    method: 'POST',
    body: JSON.stringify(credential),
  });
}

export function listPasskeys() {
  return api<{ ok: boolean; passkeys: Passkey[] }>('/passkeys/list');
}

export function deletePasskey(id: number) {
  return api<{ ok: boolean }>('/passkeys/delete', {
    method: 'POST',
    body: JSON.stringify({ id }),
  });
}

export function renamePasskey(id: number, name: string) {
  return api<{ ok: boolean }>('/passkeys/rename', {
    method: 'POST',
    body: JSON.stringify({ id, name }),
  });
}

export function getAuthInfo() {
  return api<AuthInfo>('/api/auth/info');
}

export interface Passkey {
  id: number;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface OIDCInfo {
  label: string;
  slug: string;
  logo: string;
}

export interface AuthInfo {
  passkeysEnabled: boolean;
  oidc: OIDCInfo | null;
}

// WebAuthn type helpers (simplified for browser API)
type PublicKeyCredentialCreationOptionsJSON = Record<string, unknown>;
type PublicKeyCredentialRequestOptionsJSON = Record<string, unknown>;
type AuthenticatorAttestationResponseJSON = Record<string, unknown>;
type AuthenticatorAssertionResponseJSON = Record<string, unknown>;
