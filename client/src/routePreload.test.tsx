import { describe, it, expect, vi, beforeEach } from 'vitest';

// Every lazy page the router declares gets a preload spy, keyed by the page
// its import names, so a test can say exactly which chunks a cold start asked
// for. The router is re-imported per test so the spies start clean.
const preloads = vi.hoisted(() => new Map<string, ReturnType<typeof vi.fn>>());

vi.mock('@/lib/lazyRoute', () => ({
  lazyRoute: (factory: () => Promise<unknown>) => {
    const page = /pages\/\w+\/(\w+)/.exec(factory.toString())?.[1] ?? 'unknown';
    const spy = vi.fn(() => Promise.resolve());
    preloads.set(page, spy);
    return Object.assign(() => null, { preload: spy });
  },
}));

async function coldStart(path: string, signedIn: boolean): Promise<string[]> {
  vi.resetModules();
  preloads.clear();
  const { preloadRouteChunk } = await import('./router');
  preloadRouteChunk(path, signedIn);
  return [...preloads].filter(([, spy]) => spy.mock.calls.length > 0).map(([page]) => page);
}

describe('preloadRouteChunk', () => {
  beforeEach(() => preloads.clear());

  it('sees every lazy page the router declares', async () => {
    await coldStart('/no-such-page', false);
    expect([...preloads.keys()]).toEqual(expect.arrayContaining(['Dashboard', 'Register', 'Settings']));
  });

  it('starts the dashboard chunk for a signed-in cold start to /dashboard', async () => {
    expect(await coldStart('/dashboard/', true)).toEqual(['Dashboard']);
  });

  it('fetches nothing for a signed-out cold start to /dashboard (it goes to /login)', async () => {
    expect(await coldStart('/dashboard', false)).toEqual([]);
  });

  it('starts the dashboard chunk for a signed-in user opening /, which redirects there', async () => {
    expect(await coldStart('/', true)).toEqual(['Dashboard']);
  });

  it('fetches nothing extra for a visitor opening / or /login (both are eager)', async () => {
    expect(await coldStart('/', false)).toEqual([]);
    expect(await coldStart('/login', false)).toEqual([]);
  });

  it('starts the register chunk for a visitor, the dashboard for a signed-in user', async () => {
    expect(await coldStart('/register', false)).toEqual(['Register']);
    expect(await coldStart('/register', true)).toEqual(['Dashboard']);
  });

  it('starts the settings chunk for a signed-in cold start to /settings', async () => {
    expect(await coldStart('/settings', true)).toEqual(['Settings']);
  });

  it('requests nothing for a path it does not know', async () => {
    expect(await coldStart('/no-such-page', true)).toEqual([]);
  });
});
