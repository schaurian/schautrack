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

  // On 403 (CSRF failure), retry once with fresh token
  if (res.status === 403) {
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
    csrfToken = null;
    if (on401Callback) on401Callback();
    const err = await res.json().catch(() => ({ error: 'Unauthorized' }));
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
