import { createElement, lazy, useState, type ComponentProps, type ComponentType } from 'react';

const RELOAD_FLAG = 'schautrack.chunkReloadAt';
// Long enough that a genuinely broken chunk can't reload-loop, short enough
// that a second deploy later in the same session still heals itself.
const RELOAD_COOLDOWN_MS = 30_000;

let reloading = false;

/**
 * Reload the page once for a chunk that failed to load, and report whether a
 * reload is under way.
 *
 * Asset filenames are content-hashed, so a tab that loaded index.html before a
 * deploy asks for chunks that no longer exist. Since index.html is served
 * no-cache, simply reloading picks up the new index and the new chunk names.
 *
 * Reload at most once per cooldown: if the chunk is missing for any other
 * reason, the second failure is allowed to surface instead of looping. Shared
 * by lazyRoute and the global `vite:preloadError` handler, which both see the
 * same failure — the first one reloads, the second learns it is already going.
 */
export function reloadForStaleChunk(): boolean {
  if (reloading) return true;
  const last = Number(sessionStorage.getItem(RELOAD_FLAG) ?? 0);
  if (Date.now() - last <= RELOAD_COOLDOWN_MS) return false;
  sessionStorage.setItem(RELOAD_FLAG, String(Date.now()));
  reloading = true;
  window.location.reload();
  return true;
}

/**
 * Reload once when Vite reports that a dynamic import, or one of the chunks it
 * preloads, failed — for every dynamic import, not only the lazy routes. Vite
 * dispatches `vite:preloadError` on window before rethrowing to the caller.
 */
export function installPreloadErrorReload(): void {
  window.addEventListener('vite:preloadError', () => {
    reloadForStaleChunk();
  });
}

/** Test hook: forget an earlier reload in this module instance. */
export function resetChunkReloadForTests(): void {
  reloading = false;
}

/**
 * lazy() that survives a deploy and does not suspend when it need not.
 *
 * A failed chunk reloads the page once (reloadForStaleChunk) instead of
 * handing the route to the error boundary for a navigation that would have
 * worked a second earlier.
 *
 * `preload()` starts the import ahead of the first render. If the module has
 * arrived by the time the component first renders, it renders directly:
 * React.lazy always suspends on its first render, even for a resolved import,
 * and React then holds the reveal back (its fallback throttle, ~300 ms), which
 * is the whole saving of having preloaded. The choice is made once per mount,
 * so an instance never switches between the two and loses its state.
 */
// Same call shape as React.lazy, so it stays a drop-in replacement for
// components that take props (the dashboard modals) as well as bare routes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyRoute<T extends ComponentType<any>>(factory: () => Promise<{ default: T }>) {
  let loaded: T | undefined;
  let pending: Promise<{ default: T }> | undefined;
  const load = () => {
    pending ??= factory().then((mod) => {
      loaded = mod.default;
      return mod;
    });
    return pending;
  };

  const Lazy = lazy(() =>
    load().catch((err: unknown) => {
      if (reloadForStaleChunk()) {
        // Keep React suspended while the page goes away; resolving or throwing
        // here would flash the error boundary during the reload.
        return new Promise<{ default: T }>(() => {});
      }
      throw err;
    }),
  );

  function LazyRoute(props: ComponentProps<T>) {
    const [ready] = useState(() => loaded);
    return createElement(ready ?? Lazy, props);
  }
  LazyRoute.preload = (): Promise<unknown> => load().catch(() => undefined);
  return LazyRoute;
}
