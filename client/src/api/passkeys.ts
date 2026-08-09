import { api } from './client';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';

// Server uses go-webauthn, which wraps options as {"publicKey": {...}}.
// SimpleWebAuthn's startRegistration/startAuthentication expects the inner object,
// so we unwrap here.
function unwrapPublicKey<T>(res: { publicKey?: T } & T): T {
  return (res.publicKey ?? res);
}

export async function passkeyLoginBegin() {
  const res = await api<{ publicKey?: PublicKeyCredentialRequestOptionsJSON } & PublicKeyCredentialRequestOptionsJSON>('/passkeys/login/begin', { method: 'POST' });
  return unwrapPublicKey(res);
}

export function passkeyLoginFinish(credential: AuthenticationResponseJSON) {
  return api<{ ok: boolean }>('/passkeys/login/finish', {
    method: 'POST',
    body: JSON.stringify(credential),
  });
}

export async function passkeyRegisterBegin() {
  const res = await api<{ publicKey?: PublicKeyCredentialCreationOptionsJSON } & PublicKeyCredentialCreationOptionsJSON>('/passkeys/register/begin', { method: 'POST' });
  return unwrapPublicKey(res);
}

export function passkeyRegisterFinish(credential: RegistrationResponseJSON, name: string) {
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
