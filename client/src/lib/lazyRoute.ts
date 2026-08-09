import { lazy, type ComponentType } from 'react';

const RELOAD_FLAG = 'schautrack.chunkReloadAt';
// Long enough that a genuinely broken chunk can't reload-loop, short enough
// that a second deploy later in the same session still heals itself.
const RELOAD_COOLDOWN_MS = 30_000;

/**
 * lazy() that survives a deploy.
 *
 * Asset filenames are content-hashed, so a tab that loaded index.html before a
 * deploy asks for chunks that no longer exist. The route then fails to mount
 * and the error boundary takes over — for a navigation that would have worked
 * a second earlier. Since index.html is served no-cache, simply reloading picks
 * up the new index and the new chunk names.
 *
 * Reload at most once per cooldown: if the chunk is missing for any other
 * reason, the second failure is allowed to surface instead of looping.
 */
// Same signature as React.lazy, so it stays a drop-in replacement for
// components that take props (the dashboard modals) as well as bare routes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyRoute<T extends ComponentType<any>>(factory: () => Promise<{ default: T }>) {
  return lazy(() =>
    factory().catch((err: unknown) => {
      const last = Number(sessionStorage.getItem(RELOAD_FLAG) ?? 0);
      if (Date.now() - last > RELOAD_COOLDOWN_MS) {
        sessionStorage.setItem(RELOAD_FLAG, String(Date.now()));
        window.location.reload();
        // Keep React suspended while the page goes away; resolving or throwing
        // here would flash the error boundary during the reload.
        return new Promise<{ default: T }>(() => {});
      }
      throw err;
    }),
  );
}
