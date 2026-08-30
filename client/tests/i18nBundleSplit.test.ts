import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Rollup } from 'vite';

/**
 * Bundle-split regression tests for deferred translation catalogs (issue #485).
 *
 * `src/i18n/index.ts` used to load every namespace of all eight locales with an
 * eager `import.meta.glob`, so a first-time visitor downloaded ~330 kB of
 * catalogs (~113 kB gzip) they would never read. `src/i18n/runtime.test.tsx`
 * proves the *runtime* half of the fix — that a deferred catalog still arrives
 * and still renders. It cannot prove the half that motivated the issue: that
 * the bytes actually left the entry chunk. A single `{ eager: true }` put back
 * on that glob would keep every runtime test green while silently undoing the
 * saving.
 *
 * So this file runs the real production build (in memory — `write: false`, no
 * `dist/` is touched) and asserts on the emitted chunk graph:
 *
 *   - the entry chunk carries the English catalogs, because English is the
 *     fallback language and a fetched fallback would render raw key paths on
 *     a miss;
 *   - the entry chunk carries no other locale;
 *   - every other locale/namespace pair is still reachable, as its own chunk.
 *
 * The build is the slow part here, so it runs once for the whole file.
 */

const here = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(here, '..');

const LOCALES = ['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt'];
const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'];

let chunks: Rollup.OutputChunk[] = [];
let entry: Rollup.OutputChunk;

beforeAll(async () => {
  const result = await build({
    root: clientRoot,
    logLevel: 'silent',
    build: {
      // Keep the assertions about *this* repo's chunking, not about a stale
      // dist/ some earlier command left behind, and write nothing to disk.
      write: false,
      sourcemap: false,
    },
  });

  const outputs = (Array.isArray(result) ? result : [result]) as Rollup.RollupOutput[];
  chunks = outputs
    .flatMap((o) => o.output)
    .filter((o): o is Rollup.OutputChunk => o.type === 'chunk');

  const entries = chunks.filter((c) => c.isEntry);
  expect(entries).toHaveLength(1);
  entry = entries[0];
}, 180_000);

/** Module ids of every catalog a chunk inlined, as `lng/ns` pairs. */
function catalogsIn(chunk: Rollup.OutputChunk): string[] {
  return Object.keys(chunk.modules)
    .map((id) => /src\/i18n\/locales\/([^/]+)\/([^/]+)\.json$/.exec(id))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => `${m[1]}/${m[2]}`)
    .sort();
}

describe('translation catalogs in the production bundle', () => {
  it('keeps the English fallback in the entry chunk', () => {
    const inEntry = catalogsIn(entry);
    for (const ns of NAMESPACES) {
      expect(inEntry).toContain(`en/${ns}`);
    }
  });

  it('keeps every other locale out of the entry chunk', () => {
    const foreign = catalogsIn(entry).filter((id) => !id.startsWith('en/'));
    expect(foreign).toEqual([]);
  });

  it('emits each deferred catalog as its own chunk', () => {
    const deferred = new Set(
      chunks.filter((c) => !c.isEntry).flatMap((c) => catalogsIn(c))
    );

    for (const lng of LOCALES.filter((l) => l !== 'en')) {
      for (const ns of NAMESPACES) {
        expect(deferred, `${lng}/${ns} must be split out`).toContain(`${lng}/${ns}`);
      }
    }
  });

  it('ships no non-English translated string in the entry chunk', () => {
    // Belt and braces: the module-id assertions above would miss a catalog
    // inlined by some future plugin that rewrites ids. These four strings are
    // "Loading..." in four of the deferred locales.
    for (const sample of ['Lädt...', 'Cargando...', 'Chargement...', 'Ładowanie...']) {
      expect(entry.code).not.toContain(sample);
    }
  });

  it('has a loader entry for every deferred catalog and none for English', () => {
    // The glob in src/i18n/index.ts excludes English on purpose: globbing a
    // module that is also statically imported makes Rollup report
    // INEFFECTIVE_DYNAMIC_IMPORT and keep it in the entry chunk anyway.
    const source = readFileSync(resolve(clientRoot, 'src/i18n/index.ts'), 'utf8');
    expect(source).toContain("'!./locales/en/*.json'");
    expect(source).not.toMatch(/import\.meta\.glob[^)]*eager/);
  });
});

describe('the boot sequence waits for the detected language', () => {
  it('mounts React inside i18nReady', () => {
    // A returning user with a stored non-English language must not see a frame
    // of English first. main.tsx guarantees that by creating the React root
    // only after i18nReady resolves — by which point the detected language's
    // namespaces have been fetched. Hoisting createRoot out of that callback
    // reintroduces the flash, and no runtime test would notice.
    const source = readFileSync(resolve(clientRoot, 'src/main.tsx'), 'utf8');
    const gate = source.indexOf('i18nReady.then(');
    expect(gate).toBeGreaterThan(-1);
    expect(source.indexOf('createRoot(')).toBeGreaterThan(gate);
  });
});
