import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Dependency-boundary regression tests for the barcode scanner (issue #271).
 *
 * @ericblade/quagga2 ships a Node-only image pipeline that pulls in `sharp`
 * (native libvips) and `ndarray-pixels`. Those are declared as
 * *optionalDependencies* and are only reachable from quagga2's CommonJS
 * `main` build (`lib/quagga.js`). The browser build (`dist/quagga.min.js`,
 * the `browser` field that Vite resolves) decodes via canvas and never
 * touches them.
 *
 * `sharp <0.35.0` carries the inherited libvips advisories
 * (GHSA-f88m-g3jw-g9cj), so `client/package.json` pins the transitive
 * resolution forward via npm `overrides`. These tests fail if either half of
 * that reasoning stops holding: the version floor being dropped, or the
 * Node-only pipeline leaking into the browser entry point.
 */

const here = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(here, '..');
const readText = (rel: string) => readFileSync(resolve(clientRoot, rel), 'utf8');

/** Compare dotted numeric versions. Returns <0, 0 or >0. */
function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

interface Lockfile {
  packages: Record<string, { version: string }>;
}

const lock: Lockfile = JSON.parse(readText('package-lock.json'));
const resolvedVersion = (name: string) => lock.packages[`node_modules/${name}`]?.version;

describe('barcode dependency isolation', () => {
  it('keeps the npm overrides that pin the Node-only image pipeline forward', () => {
    const pkg = JSON.parse(readText('package.json'));
    expect(pkg.overrides).toMatchObject({
      sharp: expect.any(String),
      'ndarray-pixels': expect.any(String),
    });
  });

  it('resolves sharp outside the vulnerable <0.35.0 range (GHSA-f88m-g3jw-g9cj)', () => {
    const version = resolvedVersion('sharp');
    expect(version, 'sharp missing from lockfile').toBeDefined();
    expect(
      compareVersions(version, '0.35.0'),
      `sharp resolved to ${version}, which is inside the vulnerable <0.35.0 range`
    ).toBeGreaterThanOrEqual(0);
  });

  it('resolves ndarray-pixels above the vulnerable 3.0.0-5.0.1 range', () => {
    const version = resolvedVersion('ndarray-pixels');
    expect(version, 'ndarray-pixels missing from lockfile').toBeDefined();
    expect(
      compareVersions(version, '5.0.1'),
      `ndarray-pixels resolved to ${version}, which is inside the vulnerable range`
    ).toBeGreaterThan(0);
  });

  it('keeps sharp as a single hoisted copy so the override cannot be bypassed', () => {
    // Only real `sharp` copies — not the @img/sharp-<platform> binary packages.
    const nested = Object.keys(lock.packages).filter(
      (k) => k.endsWith('node_modules/sharp') && k !== 'node_modules/sharp'
    );
    expect(nested, `unexpected nested sharp copies: ${nested.join(', ')}`).toEqual([]);
  });
});

describe('quagga2 browser entry point', () => {
  const quaggaPkg = JSON.parse(readText('node_modules/@ericblade/quagga2/package.json'));

  it('declares sharp and ndarray-pixels as optional, never as hard dependencies', () => {
    expect(Object.keys(quaggaPkg.dependencies ?? {})).not.toContain('sharp');
    expect(Object.keys(quaggaPkg.dependencies ?? {})).not.toContain('ndarray-pixels');
    expect(Object.keys(quaggaPkg.optionalDependencies ?? {})).toEqual(
      expect.arrayContaining(['sharp', 'ndarray-pixels'])
    );
  });

  it('is the bundle Vite resolves, and it never requires the Node image pipeline', () => {
    // Vite resolves the `browser` field for browser builds.
    expect(quaggaPkg.browser).toBeTruthy();
    const browserBundle = readText(`node_modules/@ericblade/quagga2/${quaggaPkg.browser}`);

    // `sharpenLine` is unrelated quagga2 image-processing code, so match on
    // module specifiers rather than a bare substring.
    for (const mod of ['sharp', 'ndarray-pixels']) {
      const specifier = new RegExp(`require\\(\\s*["']${mod}["']\\s*\\)|from\\s*["']${mod}["']`);
      expect(
        specifier.test(browserBundle),
        `quagga2 browser bundle now references "${mod}" — the Node-only image ` +
          `pipeline would ship to the browser and the isolation fix is no longer valid`
      ).toBe(false);
    }
  });
});

describe('BarcodeScanModal quagga2 usage', () => {
  const source = readText('src/pages/Dashboard/BarcodeScanModal.tsx');

  it('only calls browser-safe quagga2 APIs', () => {
    const called = [...source.matchAll(/\bQuagga\.(\w+)\(/g)].map((m) => m[1]);
    expect(called.length).toBeGreaterThan(0);

    // decodeSingle is browser-safe when handed a blob/object URL: quagga2's
    // browser build decodes it through an <img>/canvas, not through sharp.
    const browserSafe = ['init', 'start', 'stop', 'onDetected', 'offDetected', 'decodeSingle'];
    for (const api of new Set(called)) {
      expect(browserSafe, `Quagga.${api}() is not on the browser-safe allowlist`).toContain(api);
    }
  });

  it('decodes uploaded images from an object URL rather than a filesystem path', () => {
    // A filesystem path would send quagga2 down the Node/sharp branch.
    expect(source).toMatch(/URL\.createObjectURL\(file\)/);
    expect(source).toMatch(/Quagga\.decodeSingle\(/);
    expect(source).toMatch(/URL\.revokeObjectURL\(src\)/);
  });

  it('keeps the two-identical-reads false-positive guard', () => {
    expect(source).toMatch(/lastCodeRef\.current\.count\s*\+=\s*1/);
    expect(source).toMatch(/lastCodeRef\.current\.count\s*>=\s*2/);
  });

  it('tears the scanner down on close and guards a late-resolving init', () => {
    // stopScanner must detach the handler and bump the session guard so an
    // in-flight init (camera permission prompt still open) releases the camera.
    expect(source).toMatch(/Quagga\.offDetected\(\)/);
    expect(source).toMatch(/scanSessionRef\.current\+\+/);
    expect(source).toMatch(/session !== scanSessionRef\.current/);
    // The !isOpen effect must call stopScanner.
    expect(source).toMatch(/if \(!isOpen\) \{\s*\n\s*stopScanner\(\);/);
  });
});
