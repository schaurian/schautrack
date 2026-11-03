import { describe, it, expect, vi, beforeEach } from 'vitest';

// Each mock factory runs when its module is first imported, so the counters
// say which page chunks preloadRouteChunk actually requested.
const loaded = vi.hoisted(() => ({ dashboard: 0, login: 0, settings: 0 }));

vi.mock('@/pages/Dashboard/Dashboard', () => {
  loaded.dashboard++;
  return { default: () => null };
});
vi.mock('@/pages/Login/Login', () => {
  loaded.login++;
  return { default: () => null };
});
vi.mock('@/pages/Settings/Settings', () => {
  loaded.settings++;
  return { default: () => null };
});

import { preloadRouteChunk } from './router';

const settle = () => new Promise((r) => setTimeout(r, 0));

describe('preloadRouteChunk', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('starts loading the dashboard chunk for a cold start to /dashboard', async () => {
    expect(loaded.dashboard).toBe(0);
    preloadRouteChunk('/dashboard/');
    await settle();
    expect(loaded.dashboard).toBe(1);
    expect(loaded.login).toBe(0);
    expect(loaded.settings).toBe(0);
  });

  it('starts loading the login chunk for /login', async () => {
    preloadRouteChunk('/login');
    await settle();
    expect(loaded.login).toBe(1);
    expect(loaded.settings).toBe(0);
  });

  it('requests nothing for a path it does not know', async () => {
    preloadRouteChunk('/no-such-page');
    await settle();
    expect(loaded.settings).toBe(0);
  });
});
