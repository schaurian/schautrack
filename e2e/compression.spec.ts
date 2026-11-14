import { test, expect } from '@playwright/test';

// Route-level check that the server actually wires response compression,
// which unit tests of the middleware cannot see: they would stay green if the
// r.Use line in cmd/server/main.go went away. Playwright's request context
// sends Accept-Encoding: gzip, deflate, br and decodes the body, so the headers
// are what show the wire format.
test.describe('response compression', () => {
  test('a large JSON response is gzip-encoded', async ({ request }) => {
    const res = await request.get('/api/v1/openapi.json');
    expect(res.status()).toBe(200);
    expect(res.headers()['content-encoding']).toBe('gzip');
    expect(res.headers()['vary']?.toLowerCase()).toContain('accept-encoding');
    // Still the same document once decoded.
    const spec = await res.json();
    expect(spec.openapi).toMatch(/^3\./);
  });

  test('a small JSON response is sent as is', async ({ request }) => {
    const res = await request.get('/api/csrf');
    expect(res.status()).toBe(200);
    expect(res.headers()['content-encoding']).toBeUndefined();
    expect((await res.json()).token).toBeTruthy();
  });

  test('the app shell and its scripts keep the static compressor', async ({ request }) => {
    const html = await request.get('/');
    expect(html.headers()['content-type']).toContain('text/html');
    const entry = /<script type="module"[^>]*src="(\/assets\/[^"]+\.js)"/.exec(await html.text())?.[1];
    expect(entry).toBeTruthy();
    const js = await request.get(entry as string);
    expect(js.headers()['content-encoding']).toBe('gzip');
    expect(js.headers()['cache-control']).toContain('immutable');
  });
});
