import { api } from './client';

export function stepUpPasswordTOTP(password: string, token?: string) {
  return api<{ ok: boolean }>('/api/auth/step-up', {
    method: 'POST',
    body: JSON.stringify({ password, token }),
  });
}

export async function stepUpPasskeyBegin() {
  // go-webauthn wraps options as {publicKey: ...}; SimpleWebAuthn wants the inner.
  const res = await api<{ publicKey?: Record<string, unknown> } & Record<string, unknown>>(
    '/api/auth/step-up/passkey/begin',
    { method: 'POST' },
  );
  return (res.publicKey ?? res) as Record<string, unknown>;
}

export function stepUpPasskeyFinish(credential: Record<string, unknown>) {
  return api<{ ok: boolean }>('/api/auth/step-up/passkey/finish', {
    method: 'POST',
    body: JSON.stringify(credential),
  });
}
