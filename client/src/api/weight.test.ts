import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { upsertWeight } from './weight';

/**
 * These assert the wire shape of a weight save, because that shape is the whole
 * fix: the server leaves alone whichever of the two columns the request omits,
 * so a key that should not be there is a silent overwrite rather than an error.
 */

type Sent = { url: string; body: Record<string, unknown> };

function stubFetch(): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === '/api/csrf') {
        return new Response(JSON.stringify({ token: 'test-csrf' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      sent.push({ url, body: JSON.parse(String(init?.body ?? '{}')) });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );
  return sent;
}

describe('upsertWeight', () => {
  let sent: Sent[];
  beforeEach(() => {
    sent = stubFetch();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('omits weight when only a body fat is being saved', async () => {
    await upsertWeight({ date: '2026-08-08', body_fat: 24.3 });
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe('/weight/upsert');
    // The regression: sending the dashboard's cached weight back here reverts
    // a newer weight logged from another device.
    expect(sent[0].body).not.toHaveProperty('weight');
    expect(sent[0].body).toEqual({ date: '2026-08-08', body_fat: 24.3 });
  });

  it('sends an explicit null to clear a body fat, still without a weight', async () => {
    await upsertWeight({ date: '2026-08-08', body_fat: null });
    expect(sent[0].body).not.toHaveProperty('weight');
    expect(sent[0].body).toEqual({ date: '2026-08-08', body_fat: null });
  });

  it('omits body_fat when only a weight is being saved', async () => {
    // The mirror-image guarantee that already existed: a weight-only save must
    // not wipe a reading taken from the same day's scale.
    await upsertWeight({ date: '2026-08-08', weight: 82 });
    expect(sent[0].body).not.toHaveProperty('body_fat');
    expect(sent[0].body).toEqual({ date: '2026-08-08', weight: 82 });
  });
});
