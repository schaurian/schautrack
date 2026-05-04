import { useStepUpStore } from '@/stores/stepUpStore';

let csrfToken: string | null = null;
let on401Callback: (() => void) | null = null;

export function setOn401(callback: () => void) {
  on401Callback = callback;
}

async function fetchCsrfToken(): Promise<string> {
  const res = await fetch('/api/csrf');
  if (!res.ok) throw new Error('Failed to fetch CSRF token');
  const data = await res.json();
  csrfToken = data.token;
  return csrfToken!;
}

export async function getCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  return fetchCsrfToken();
}

export async function api<T = unknown>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');

  if (options.method && options.method !== 'GET') {
    const token = await getCsrfToken();
    headers.set('X-CSRF-Token', token);
    if (options.body && typeof options.body === 'string' && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  }

  const res = await fetch(url, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });

  // 403 means either CSRF failure or step-up required. Inspect the body to
  // decide. clone() so we can still consume the body in the CSRF retry path.
  if (res.status === 403) {
    const body = await res.clone().json().catch(() => null) as
      | { requireStepUp?: boolean; methods?: string[]; totpRequired?: boolean }
      | null;

    if (body?.requireStepUp) {
      // Suspend this request until the user completes step-up. The modal
      // calls retry() on success, which re-runs the original api() call;
      // its result resolves the promise we return here. So callers see a
      // normal async response (or a rejection if the user cancels).
      return new Promise<T>((resolve, reject) => {
        useStepUpStore.getState().enqueue({
          methods: body.methods ?? [],
          totpRequired: !!body.totpRequired,
          retry: async () => {
            try {
              resolve(await api<T>(url, options));
            } catch (err) {
              reject(err);
            }
          },
          cancel: () => reject(new ApiError(403, 'Step-up cancelled', {})),
        });
      });
    }

    // CSRF failure — refresh token and retry once.
    csrfToken = null;
    const freshToken = await fetchCsrfToken();
    headers.set('X-CSRF-Token', freshToken);
    const retry = await fetch(url, { ...options, headers, credentials: 'same-origin' });
    if (!retry.ok) {
      const err = await retry.json().catch(() => ({ error: 'Request failed' }));
      throw new ApiError(retry.status, err.error || 'Request failed', err);
    }
    return retry.json();
  }

  if (res.status === 401) {
    // 401 from a step-up endpoint usually means the password / TOTP / passkey
    // the user just entered didn't validate — the modal stays open and shows
    // an inline error. EXCEPTION: if the body has lockout:true, the server
    // destroyed the session after too many failed attempts; in that case we
    // do want the on401 redirect path (clear user, kick to /login).
    const isStepUpEndpoint = url.startsWith('/api/auth/step-up');
    const err = await res.json().catch(() => ({ error: 'Unauthorized' })) as
      { error?: string; lockout?: boolean };
    const sessionKilled = !isStepUpEndpoint || err.lockout === true;
    if (sessionKilled) {
      csrfToken = null;
      if (on401Callback) on401Callback();
    }
    throw new ApiError(401, err.error || 'Unauthorized', err);
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new ApiError(res.status, err.error || 'Request failed', err);
  }

  // Handle empty responses
  const contentType = res.headers.get('content-type');
  if (!contentType || !contentType.includes('application/json')) {
    return {} as T;
  }

  return res.json();
}

export class ApiError extends Error {
  status: number;
  data: Record<string, unknown>;

  constructor(status: number, message: string, data: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.data = data;
  }
}
