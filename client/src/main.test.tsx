import { describe, it, expect, vi } from 'vitest';

// Boot wiring: what main.tsx does before React mounts. Everything heavy is
// stubbed; the assertions are about the two calls that a refactor could drop
// without any other test noticing.
const calls = vi.hoisted(() => ({
  preload: vi.fn(),
  install: vi.fn(),
  render: vi.fn(),
}));

vi.mock('./router', () => ({ preloadRouteChunk: calls.preload }));
vi.mock('@/lib/lazyRoute', () => ({ installPreloadErrorReload: calls.install }));
vi.mock('@/lib/sessionHint', () => ({ readSessionHint: () => true }));
vi.mock('./App', () => ({ default: () => null }));
vi.mock('@/i18n', () => ({ i18nReady: Promise.resolve() }));
vi.mock('react-dom/client', () => ({ createRoot: () => ({ render: calls.render }) }));

describe('main.tsx boot', () => {
  it('installs the stale-chunk reload, then preloads the cold-start page', async () => {
    window.history.replaceState(null, '', '/dashboard');
    document.body.innerHTML = '<div id="root"></div>';
    await import('./main');

    expect(calls.install).toHaveBeenCalledTimes(1);
    expect(calls.preload).toHaveBeenCalledWith('/dashboard', true);
    // Before the preload: a failing first chunk must already be handled.
    expect(calls.install.mock.invocationCallOrder[0]).toBeLessThan(calls.preload.mock.invocationCallOrder[0]);
    await vi.waitFor(() => expect(calls.render).toHaveBeenCalledTimes(1));
    expect(calls.preload.mock.invocationCallOrder[0]).toBeLessThan(calls.render.mock.invocationCallOrder[0]);
  });
});
