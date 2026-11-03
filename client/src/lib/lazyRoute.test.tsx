import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Component, Suspense, type ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import { installPreloadErrorReload, lazyRoute, reloadForStaleChunk, resetChunkReloadForTests } from './lazyRoute';

const reload = vi.fn();
const realLocation = window.location;

beforeEach(() => {
  reload.mockReset();
  sessionStorage.clear();
  resetChunkReloadForTests();
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, reload } });
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation });
  vi.useRealTimers();
});

function Page({ label }: { label: string }) {
  return <p>{label}</p>;
}

describe('lazyRoute', () => {
  it('renders a preloaded page in the first commit, without suspending', async () => {
    const Lazy = lazyRoute(() => Promise.resolve({ default: Page }));
    await Lazy.preload();
    render(
      <Suspense fallback={<p>fallback</p>}>
        <Lazy label="ready" />
      </Suspense>,
    );
    // Synchronous query: no await, no act flush — a suspended render would
    // show the fallback here.
    expect(screen.getByText('ready')).toBeInTheDocument();
    expect(screen.queryByText('fallback')).toBeNull();
  });

  it('suspends and then renders a page that was not preloaded', async () => {
    const Lazy = lazyRoute(() => Promise.resolve({ default: Page }));
    render(
      <Suspense fallback={<p>fallback</p>}>
        <Lazy label="later" />
      </Suspense>,
    );
    expect(screen.getByText('fallback')).toBeInTheDocument();
    expect(await screen.findByText('later')).toBeInTheDocument();
  });

  it('imports once for preload and render together', async () => {
    const factory = vi.fn(() => Promise.resolve({ default: Page }));
    const Lazy = lazyRoute(factory);
    await Lazy.preload();
    render(
      <Suspense fallback={null}>
        <Lazy label="x" />
      </Suspense>,
    );
    expect(factory).toHaveBeenCalledTimes(1);
  });

  it('reloads once when the chunk fails, instead of throwing to the error boundary', async () => {
    const Lazy = lazyRoute(() => Promise.reject(new Error('Failed to fetch dynamically imported module')));
    render(
      <Suspense fallback={<p>fallback</p>}>
        <Lazy label="never" />
      </Suspense>,
    );
    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
    expect(screen.getByText('fallback')).toBeInTheDocument();
  });
});

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? <p>error screen</p> : this.props.children;
  }
}

describe('a chunk failure during a reload already under way', () => {
  it('keeps the route suspended instead of showing the error screen', async () => {
    // The global handler saw the same broken deploy first and is reloading.
    expect(reloadForStaleChunk()).toBe(true);
    const Lazy = lazyRoute(() => Promise.reject(new Error('Failed to fetch dynamically imported module')));
    render(
      <Boundary>
        <Suspense fallback={<p>fallback</p>}>
          <Lazy label="never" />
        </Suspense>
      </Boundary>,
    );
    // Long enough for React to retry the failed lazy and commit whatever it
    // decides (it throttles that by ~300 ms); a thrown error shows by then.
    await new Promise((r) => setTimeout(r, 800));
    expect(screen.queryByText('error screen')).toBeNull();
    expect(screen.getByText('fallback')).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
  });
});

describe('vite:preloadError', () => {
  it('reloads the page once for a failed dynamic import anywhere', () => {
    installPreloadErrorReload();
    window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }));
    expect(reload).toHaveBeenCalledTimes(1);
    // The second failure of the same broken load must not reload again.
    window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});

describe('reloadForStaleChunk', () => {
  it('reloads at most once per 30 s, across page loads', () => {
    vi.useFakeTimers({ now: 1_000_000 });
    expect(reloadForStaleChunk()).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);

    // A fresh page load (module state gone, sessionStorage kept) inside the
    // cooldown: a chunk that is still missing must surface, not loop.
    resetChunkReloadForTests();
    vi.setSystemTime(1_000_000 + 10_000);
    expect(reloadForStaleChunk()).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);

    resetChunkReloadForTests();
    vi.setSystemTime(1_000_000 + 31_000);
    expect(reloadForStaleChunk()).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });
});
