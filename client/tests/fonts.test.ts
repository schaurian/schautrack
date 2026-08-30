import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';

/**
 * Regression tests for the self-hosted web fonts (issue #484).
 *
 * The bug these exist to prevent: @fontsource's per-subset stylesheets
 * (`latin-400.css`, `latin-ext-400.css`, …) deliberately omit `unicode-range`,
 * because each is meant to be the *only* stylesheet for its family. Importing
 * two of them stacks two @font-face rules with an identical
 * family/style/weight/unicode-range tuple, so the later rule replaces the
 * earlier one instead of composing with it. The result is that the browser
 * resolves the family to the latin-ext file — which contains no ASCII glyphs at
 * all — and every page downloads the big Latin-Extended cut whether or not a
 * single Polish character is on screen.
 *
 * So the checks below assert the three properties that make
 * `src/styles/fonts.css` correct, all of which the shipped version violated:
 *
 *  1. every @font-face carries a `unicode-range`,
 *  2. no two rules collide on (family, style, weight, unicode-range), and
 *  3. the ranges match the ones @fontsource itself publishes.
 *
 * Plus the thing the issue actually asks for: that the subsets we keep really
 * do cover every character the eight supported locales use. That one is checked
 * against the fonts' real `cmap` tables, not against the declared ranges — a
 * codepoint can sit inside `unicode-range` and still be absent from the file.
 */

const here = dirname(fileURLToPath(import.meta.url));
const clientRoot = resolve(here, '..');
const fontsCssPath = resolve(clientRoot, 'src/styles/fonts.css');
const fontsCss = readFileSync(fontsCssPath, 'utf8');
const nodeModules = resolve(clientRoot, 'node_modules');

/** Weights each family is expected to ship, per the design. */
const EXPECTED_WEIGHTS: Record<string, number[]> = {
  'Noto Sans': [400, 500, 600, 700],
  'Space Grotesk': [500, 700],
};

/** The two subsets the supported locales need. */
const EXPECTED_SUBSETS = ['latin', 'latin-ext'];

interface FontFace {
  family: string;
  style: string;
  weight: string;
  src: string;
  unicodeRange: string | undefined;
  /** The @fontsource package path inside the single `url()`. */
  file: string;
}

function parseFontFaces(css: string): FontFace[] {
  const faces: FontFace[] = [];
  for (const [, body] of css.matchAll(/@font-face\s*\{([^}]*)\}/g)) {
    const decl = (name: string): string | undefined => {
      const m = body.match(new RegExp(`(?:^|;)\\s*${name}\\s*:\\s*([^;]+)`, 'i'));
      return m ? m[1].replace(/\s+/g, ' ').trim() : undefined;
    };
    const src = decl('src') ?? '';
    const urls = [...src.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/g)].map((m) => m[1]);
    expect(urls, `each @font-face declares exactly one url() in ${src}`).toHaveLength(1);
    faces.push({
      family: (decl('font-family') ?? '').replace(/['"]/g, ''),
      style: decl('font-style') ?? '',
      weight: decl('font-weight') ?? '',
      src,
      unicodeRange: decl('unicode-range')?.replace(/\s+/g, ''),
      file: urls[0],
    });
  }
  return faces;
}

const faces = parseFontFaces(fontsCss);

/** Reads the tables out of a WOFF 1.0 container. */
function woffTables(path: string): Map<string, Buffer> {
  const d = readFileSync(path);
  expect(d.subarray(0, 4).toString('latin1'), `${path} is a WOFF container`).toBe('wOFF');
  const numTables = d.readUInt16BE(12);
  const out = new Map<string, Buffer>();
  for (let i = 0; i < numTables; i++) {
    const e = 44 + i * 20;
    const tag = d.subarray(e, e + 4).toString('latin1');
    const offset = d.readUInt32BE(e + 4);
    const compLength = d.readUInt32BE(e + 8);
    const origLength = d.readUInt32BE(e + 12);
    const raw = d.subarray(offset, offset + compLength);
    out.set(tag, compLength === origLength ? raw : inflateSync(raw));
  }
  return out;
}

/** Every codepoint the font has a glyph for, from its `cmap`. */
function codepoints(cmap: Buffer): Set<number> {
  let chosen: { offset: number; format: number } | undefined;
  const n = cmap.readUInt16BE(2);
  for (let i = 0; i < n; i++) {
    const platform = cmap.readUInt16BE(4 + i * 8);
    const encoding = cmap.readUInt16BE(6 + i * 8);
    const offset = cmap.readUInt32BE(8 + i * 8);
    const unicode =
      (platform === 3 && (encoding === 1 || encoding === 10)) ||
      (platform === 0 && encoding >= 3 && encoding <= 6);
    if (!unicode) continue;
    const format = cmap.readUInt16BE(offset);
    // Prefer format 12 (full Unicode) over format 4 (BMP only).
    if (!chosen || format === 12) chosen = { offset, format };
  }
  if (!chosen) throw new Error('no Unicode cmap subtable');

  const cps = new Set<number>();
  const { offset, format } = chosen;
  if (format === 4) {
    const segCount = cmap.readUInt16BE(offset + 6) / 2;
    const endBase = offset + 14;
    const startBase = endBase + segCount * 2 + 2;
    const deltaBase = startBase + segCount * 2;
    const rangeBase = deltaBase + segCount * 2;
    for (let i = 0; i < segCount; i++) {
      const end = cmap.readUInt16BE(endBase + i * 2);
      const start = cmap.readUInt16BE(startBase + i * 2);
      if (start === 0xffff) continue;
      const delta = cmap.readInt16BE(deltaBase + i * 2);
      const rangeOffset = cmap.readUInt16BE(rangeBase + i * 2);
      for (let c = start; c <= end; c++) {
        let glyph: number;
        if (rangeOffset === 0) {
          glyph = (c + delta) & 0xffff;
        } else {
          const at = rangeBase + i * 2 + rangeOffset + (c - start) * 2;
          if (at + 2 > cmap.length) continue;
          glyph = cmap.readUInt16BE(at);
          if (glyph !== 0) glyph = (glyph + delta) & 0xffff;
        }
        if (glyph !== 0) cps.add(c);
      }
    }
  } else if (format === 12) {
    const groups = cmap.readUInt32BE(offset + 12);
    for (let i = 0; i < groups; i++) {
      const g = offset + 16 + i * 12;
      const start = cmap.readUInt32BE(g);
      const end = cmap.readUInt32BE(g + 4);
      for (let c = start; c <= end; c++) cps.add(c);
    }
  } else {
    throw new Error(`unsupported cmap format ${format}`);
  }
  return cps;
}

/** Resolves a `@fontsource/...woff2` url to the sibling `.woff` in node_modules. */
function woffSibling(file: string): string {
  return resolve(nodeModules, file.replace(/\.woff2$/, '.woff'));
}

describe('self-hosted font stylesheet', () => {
  it('declares exactly the intended families, weights and subsets', () => {
    const seen = faces.map((f) => `${f.family}/${f.weight}/${subsetOf(f.file)}`).sort();
    const want = Object.entries(EXPECTED_WEIGHTS)
      .flatMap(([family, weights]) =>
        weights.flatMap((w) => EXPECTED_SUBSETS.map((s) => `${family}/${w}/${s}`))
      )
      .sort();
    expect(seen).toEqual(want);
  });

  it('gives every @font-face a unicode-range', () => {
    // Without this, two rules for the same family/weight collide and the last
    // one silently wins — the exact bug that shipped the ASCII-less latin-ext
    // cut to every visitor.
    const missing = faces.filter((f) => !f.unicodeRange).map((f) => f.file);
    expect(missing).toEqual([]);
  });

  it('never lets two faces collide on the same descriptor tuple', () => {
    const keys = faces.map((f) => `${f.family}|${f.style}|${f.weight}|${f.unicodeRange}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('uses the unicode-ranges @fontsource publishes for these subsets', () => {
    // If @fontsource re-cuts a subset, the ranges here go stale and text in the
    // moved codepoints would fall back to a system font. Diff them.
    for (const face of faces) {
      const pkg = face.file.split('/files/')[0];
      const upstream = readFileSync(resolve(nodeModules, pkg, `${face.weight}.css`), 'utf8');
      const basename = face.file.split('/').pop();
      const block = upstream
        .split('@font-face')
        .find((b) => b.includes(basename!.replace(/\.woff2$/, '.woff2')));
      expect(block, `${basename} still exists upstream`).toBeDefined();
      const range = block!.match(/unicode-range:\s*([^;]+)/)?.[1].replace(/\s+/g, '');
      expect(face.unicodeRange, `unicode-range for ${basename}`).toBe(range);
    }
  });

  it('ships woff2 only, with every referenced file present', () => {
    for (const face of faces) {
      expect(face.file, 'font url is a woff2 in @fontsource').toMatch(
        /^@fontsource\/[^/]+\/files\/.+\.woff2$/
      );
      expect(face.src, 'no legacy woff fallback — woff2 is universally supported').not.toMatch(
        /format\(['"]woff['"]\)/
      );
      expect(existsSync(resolve(nodeModules, face.file)), `${face.file} exists`).toBe(true);
    }
  });

  it('is the only place the app pulls fonts in', () => {
    const main = readFileSync(resolve(clientRoot, 'src/main.tsx'), 'utf8');
    expect(main).toContain("import '@/styles/fonts.css';");
    // A bare @fontsource stylesheet import would re-introduce either the
    // unused scripts or the unicode-range-less subset files.
    expect(main).not.toMatch(/@fontsource\/[^'"]+\.css/);
  });
});

function subsetOf(file: string): string {
  const m = file.match(/-(latin-ext|latin)-\d+-normal\.woff2$/);
  if (!m) throw new Error(`cannot read subset from ${file}`);
  return m[1];
}

describe('locale coverage', () => {
  /** Every character used by every supported locale's translations. */
  const localeChars = (() => {
    const dir = resolve(clientRoot, 'src/i18n/locales');
    const chars = new Map<string, Set<string>>();
    for (const locale of readdirSync(dir)) {
      const set = new Set<string>();
      for (const file of readdirSync(resolve(dir, locale))) {
        const walk = (node: unknown): void => {
          if (typeof node === 'string') for (const c of node) set.add(c);
          else if (Array.isArray(node)) node.forEach(walk);
          else if (node && typeof node === 'object')
            for (const [k, v] of Object.entries(node)) {
              for (const c of k) set.add(c);
              walk(v);
            }
        };
        walk(JSON.parse(readFileSync(resolve(dir, locale, file), 'utf8')));
      }
      chars.set(locale, set);
    }
    return chars;
  })();

  /**
   * Characters no Latin cut can supply, which fall back to the platform's
   * symbol/emoji font by design. Listed explicitly so that a *new* uncovered
   * character — a locale gaining Greek or Cyrillic, say — fails instead of
   * quietly rendering in a fallback face.
   */
  const FALLBACK_BY_DESIGN = new Set(['\n', '⚠', '🔄']);

  it('covers all eight supported locales', () => {
    expect([...localeChars.keys()].sort()).toEqual(['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt']);
  });

  it('has a real glyph for every locale character in both families', () => {
    for (const [family, weights] of Object.entries(EXPECTED_WEIGHTS)) {
      const covered = new Set<number>();
      for (const face of faces.filter((f) => f.family === family && f.weight === String(weights[0])))
        for (const cp of codepoints(woffTables(woffSibling(face.file)).get('cmap')!)) covered.add(cp);

      for (const [locale, chars] of localeChars) {
        const missing = [...chars].filter(
          (c) => !covered.has(c.codePointAt(0)!) && !FALLBACK_BY_DESIGN.has(c)
        );
        expect(missing, `${family} covers ${locale}`).toEqual([]);
      }
    }
  });

  it('needs latin-ext for Polish and only for Polish', () => {
    // The justification for keeping latin-ext at all. If this ever flips, the
    // subset can be dropped from the critical path entirely.
    const latinOnly = new Set<number>();
    const latinFace = faces.find((f) => f.family === 'Noto Sans' && subsetOf(f.file) === 'latin')!;
    for (const cp of codepoints(woffTables(woffSibling(latinFace.file)).get('cmap')!))
      latinOnly.add(cp);

    const needsExt = new Map<string, string>();
    for (const [locale, chars] of localeChars) {
      const beyond = [...chars]
        .filter((c) => !latinOnly.has(c.codePointAt(0)!) && !FALLBACK_BY_DESIGN.has(c))
        .sort();
      if (beyond.length > 0) needsExt.set(locale, beyond.join(''));
    }
    expect([...needsExt.keys()]).toEqual(['pl']);
    // Polish diacritics only — ó/Ó are in the latin cut and never show up here.
    const POLISH = new Set('ąćęłńśźżĄĆĘŁŃŚŹŻ');
    expect([...needsExt.get('pl')!].filter((c) => !POLISH.has(c))).toEqual([]);
    expect(needsExt.get('pl')!.length).toBeGreaterThan(0);
  });
});
