import { describe, it, expect, beforeAll } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Rollup } from 'vite';

/**
 * What a cold start downloads before it can render anything: the entry chunk
 * and every chunk it imports statically (Vite emits those as modulepreload
 * links in index.html). Dynamic imports are not on that path.
 *
 * Some modules are needed only after a user action (the first-login tour) or
 * only on a page that a cold start rarely opens. One stray static import pulls
 * any of them back into the startup bundle without failing anything else, so
 * this runs the real production build (in memory) and walks the chunk graph.
 *
 * The opposite also matters. Landing and Login are the signed-out cold-start
 * pages and must render in the frame the session check lands: a lazy page
 * suspends on its first render, and React then holds the reveal back by ~300
 * ms. The step-up modal guards security-sensitive actions and must never
 * depend on a chunk that can fail to load.
 */

const here = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(here, '..');

const DEFERRED: { what: string; id: RegExp }[] = [
  { what: 'the welcome tour', id: /src\/components\/Onboarding\// },
  { what: 'the register page', id: /src\/pages\/Register\// },
  { what: 'the password-reset pages', id: /src\/pages\/(ForgotPassword|ResetPassword)\// },
  { what: 'the dashboard page', id: /src\/pages\/Dashboard\// },
];

const EAGER: { what: string; id: RegExp }[] = [
  { what: 'the landing page', id: /src\/pages\/Landing\/Landing\.tsx$/ },
  { what: 'the login page', id: /src\/pages\/Login\/Login\.tsx$/ },
  { what: 'the step-up modal', id: /src\/components\/StepUpModal\.tsx$/ },
  { what: 'the WebAuthn library the login and step-up use', id: /node_modules\/@simplewebauthn\// },
];

let critical: string[] = [];

/** Module ids of the given chunks plus everything they import statically. */
function closure(byName: Map<string, Rollup.OutputChunk>, roots: string[]): string[] {
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length) {
    const name = queue.pop() as string;
    if (seen.has(name)) continue;
    seen.add(name);
    queue.push(...(byName.get(name)?.imports ?? []));
  }
  return [...seen].flatMap((n) => Object.keys(byName.get(n)?.modules ?? {}));
}

beforeAll(async () => {
  const result = await build({
    root: clientRoot,
    logLevel: 'silent',
    build: { write: false, sourcemap: false },
  });
  const outputs = (Array.isArray(result) ? result : [result]) as Rollup.RollupOutput[];
  const chunks = outputs
    .flatMap((o) => o.output)
    .filter((o): o is Rollup.OutputChunk => o.type === 'chunk');
  const byName = new Map(chunks.map((c) => [c.fileName, c]));

  const entries = chunks.filter((c) => c.isEntry);
  expect(entries).toHaveLength(1);

  critical = closure(byName, [entries[0].fileName]);
  expect(critical.length).toBeGreaterThan(0);
}, 180_000);

describe('the startup bundle', () => {
  it.each(DEFERRED)('leaves out $what', ({ id }) => {
    expect(critical.filter((m) => id.test(m))).toEqual([]);
  });

  it.each(EAGER)('carries $what', ({ id }) => {
    expect(critical.some((m) => id.test(m))).toBe(true);
  });

  it('still carries React and the router', () => {
    // Guards the walk itself: an empty or wrong closure would pass every
    // "leaves out" case above.
    expect(critical.some((m) => /node_modules\/react-dom\//.test(m))).toBe(true);
    expect(critical.some((m) => /src\/router\.tsx$/.test(m))).toBe(true);
  });
});
