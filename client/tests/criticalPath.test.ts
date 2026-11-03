import { describe, it, expect, beforeAll } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Rollup } from 'vite';

/**
 * What a cold start downloads before it can render anything: the entry chunk
 * and every chunk it imports statically (Vite emits those as modulepreload
 * links in index.html). Dynamic imports are not on that path.
 *
 * These modules are needed only after a user action — a step-up prompt, the
 * first-login tour, the passkey button — or only on a signed-out page that a
 * returning user (and every Android cold start, which opens /dashboard) never
 * renders. One stray static import pulls any of them back into the startup
 * bundle without failing anything else, so this runs the real production build
 * (in memory) and walks the chunk graph.
 */

const here = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(here, '..');

const DEFERRED: { what: string; id: RegExp }[] = [
  { what: 'the WebAuthn library', id: /node_modules\/@simplewebauthn\// },
  { what: 'Radix Dialog', id: /node_modules\/@radix-ui\/react-dialog\// },
  { what: 'the step-up modal', id: /src\/components\/StepUpModal\.tsx$/ },
  { what: 'the welcome tour', id: /src\/components\/Onboarding\// },
  { what: 'the landing page', id: /src\/pages\/Landing\// },
  { what: 'the login page', id: /src\/pages\/Login\// },
  { what: 'the register page', id: /src\/pages\/Register\// },
  { what: 'the dashboard page', id: /src\/pages\/Dashboard\// },
];

let critical: string[] = [];
let loginPage: string[] = [];

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
  const loginChunk = chunks.find((c) => Object.keys(c.modules).some((m) => /src\/pages\/Login\/Login\.tsx$/.test(m)));
  expect(loginChunk).toBeDefined();
  loginPage = closure(byName, [(loginChunk as Rollup.OutputChunk).fileName]);
  expect(critical.length).toBeGreaterThan(0);
}, 180_000);

describe('the login page', () => {
  it('fetches the WebAuthn library only when the passkey button is used', () => {
    // A cold start to /login downloads the login chunk and its static imports;
    // the passkey helper is for one button on it.
    expect(loginPage.filter((m) => /node_modules\/@simplewebauthn\//.test(m))).toEqual([]);
  });
});

describe('the startup bundle', () => {
  it.each(DEFERRED)('leaves out $what', ({ id }) => {
    expect(critical.filter((m) => id.test(m))).toEqual([]);
  });

  it('still carries React and the router', () => {
    // Guards the walk itself: an empty or wrong closure would pass every
    // "leaves out" case above.
    expect(critical.some((m) => /node_modules\/react-dom\//.test(m))).toBe(true);
    expect(critical.some((m) => /src\/router\.tsx$/.test(m))).toBe(true);
  });
});
