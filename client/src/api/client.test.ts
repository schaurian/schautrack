import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n, { i18nReady } from '@/i18n';
import { api } from './client';

// A failure with no JSON error body (a proxy's HTML 502, an empty 500) used to
// surface the client's own English fallback in a toast whatever the language.

function stubFetch(status: number) {
  vi.stubGlobal(
    'fetch',
    // eslint-disable-next-line @typescript-eslint/require-await -- async without await is the plainest way for this mock to satisfy fetch's Promise<Response> contract
    vi.fn(async () => new Response('<html>Bad Gateway</html>', { status, headers: { 'Content-Type': 'text/html' } })),
  );
}

describe('api() fallback error message', () => {
  afterEach(async () => {
    vi.unstubAllGlobals();
    await i18n.changeLanguage('en');
  });

  it('is translated when the server sends no error body', async () => {
    await i18nReady;
    await i18n.changeLanguage('de');
    stubFetch(502);
    await expect(api('/api/anything')).rejects.toThrow('Anfrage fehlgeschlagen');
  });

  it('prefers the server message when there is one', async () => {
    await i18nReady;
    await i18n.changeLanguage('de');
    vi.stubGlobal(
      'fetch',
      // eslint-disable-next-line @typescript-eslint/require-await -- see above
      vi.fn(async () => new Response(JSON.stringify({ error: 'Invalid date' }), { status: 400, headers: { 'Content-Type': 'application/json' } })),
    );
    await expect(api('/api/anything')).rejects.toThrow('Invalid date');
  });
});
