/**
 * Whether this browser was signed in when the app last checked.
 *
 * The session cookie is HttpOnly, so at boot — before /api/me answers — the
 * client cannot know whether it is signed in. This remembered answer lets the
 * boot preload pick the page the router is about to render (the dashboard for
 * a returning user, nothing extra for a visitor). It is only ever a hint: the
 * router still decides from /api/me, so a stale value costs one unused chunk.
 */
const KEY = 'schautrack.signedIn';

export function readSessionHint(): boolean {
  try {
    return localStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
}

export function writeSessionHint(signedIn: boolean): void {
  try {
    if (signedIn) localStorage.setItem(KEY, '1');
    else localStorage.removeItem(KEY);
  } catch {
    // Storage unavailable (private mode, quota): the hint is an optimisation.
  }
}
