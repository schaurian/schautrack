import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Quagga from '@ericblade/quagga2';

/**
 * Fixture-based decode coverage for the barcode upload path (issue #271).
 *
 * `tests/barcodeDeps.test.ts` asserts the *shape* of the dependency fix — which
 * versions resolve, and that the Node-only image pipeline stays out of the
 * browser bundle. Those are all static assertions: nothing there ever decodes an
 * image, so an override that silently broke real decoding would still pass.
 *
 * This file closes that gap. It runs generated EAN-13 / EAN-8 / UPC-A / UPC-E
 * images through quagga2 using *exactly* the decoder configuration
 * `BarcodeScanModal.tsx` passes for uploads, and it exercises the overridden
 * `sharp` + `ndarray-pixels` pair for real rather than just reading their
 * version numbers out of the lockfile.
 *
 * Scope, stated honestly: vitest runs with `environment: 'node'`, so quagga2
 * resolves its CommonJS `main` build and loads pixels through sharp. The browser
 * build reaches the same reader and locator code through an <img>/canvas
 * front-end instead. So this covers the decoding algorithms and the shipped
 * decoder config, *not* the canvas front-end, and it is not a substitute for
 * on-device camera testing. Regenerate the fixtures with
 * `node scripts/generate-barcode-fixtures.mjs`.
 */

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(here, 'fixtures/barcodes');
const modalSource = readFileSync(
  resolve(here, '../src/pages/Dashboard/BarcodeScanModal.tsx'),
  'utf8'
);

/** The reader list BarcodeScanModal.tsx ships for the upload path. */
const READERS = ['ean_reader', 'ean_8_reader', 'upc_reader', 'upc_e_reader'];

/** The validation gate the modal applies before it calls OpenFoodFacts. */
const LOOKUP_GUARD = /^\d{8,13}$/;

function decodeFixture(file: string): Promise<string | null> {
  return new Promise((res) => {
    Quagga.decodeSingle(
      {
        src: resolve(fixtureDir, file),
        numOfWorkers: 0,
        decoder: { readers: READERS },
        locate: true,
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (result: any) => res(result?.codeResult?.code ?? null)
    );
  });
}

describe('barcode fixture decoding', () => {
  // quagga2 decodes a full frame per case; give each one room on a cold CI box.
  const TIMEOUT = 30_000;

  it(
    'decodes an EAN-13 symbol',
    async () => {
      expect(await decodeFixture('ean13-4006381333931.png')).toBe('4006381333931');
    },
    TIMEOUT
  );

  it(
    'decodes an EAN-8 symbol',
    async () => {
      expect(await decodeFixture('ean8-96385074.png')).toBe('96385074');
    },
    TIMEOUT
  );

  it(
    'decodes a UPC-A symbol, normalised to its 13-digit EAN-13 form',
    async () => {
      // `ean_reader` precedes `upc_reader` in the shipped list, so a UPC-A symbol
      // is reported in its EAN-13 representation — the 12 digits with a leading
      // zero. Pinned because it is what actually reaches the product lookup; with
      // only `upc_reader` enabled the same image reads as '036000291452'.
      const code = await decodeFixture('upca-036000291452.png');
      expect(code).toBe('0036000291452');
      expect(code!.slice(1)).toBe('036000291452');
    },
    TIMEOUT
  );

  it(
    'decodes a UPC-E symbol',
    async () => {
      expect(await decodeFixture('upce-04252614.png')).toBe('04252614');
    },
    TIMEOUT
  );

  it(
    'does not hallucinate a code from a blank frame',
    async () => {
      expect(await decodeFixture('blank.png')).toBeNull();
    },
    TIMEOUT
  );

  it(
    'produces codes the modal will actually forward to lookup',
    async () => {
      // A decode that the modal's own guard rejects is a decode users never see.
      const codes = await Promise.all([
        decodeFixture('ean13-4006381333931.png'),
        decodeFixture('ean8-96385074.png'),
        decodeFixture('upca-036000291452.png'),
        decodeFixture('upce-04252614.png'),
      ]);
      for (const code of codes) {
        expect(code, 'fixture failed to decode at all').not.toBeNull();
        expect(LOOKUP_GUARD.test(code!), `${code} is rejected by the modal's guard`).toBe(true);
      }
    },
    TIMEOUT * 2
  );
});

describe('decode fixtures track the shipped configuration', () => {
  it('uses the same reader list as BarcodeScanModal', () => {
    // If the modal's readers change, these fixtures stop describing production.
    const match = modalSource.match(/readers:\s*\[([^\]]*)\]/);
    expect(match, 'could not find the readers array in BarcodeScanModal.tsx').not.toBeNull();
    const shipped = [...match![1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(shipped).toEqual(READERS);
  });

  it('applies the same lookup guard as BarcodeScanModal', () => {
    expect(modalSource).toContain(LOOKUP_GUARD.source);
  });

  it('still scans with locate enabled, which the fixtures are drawn for', () => {
    // The fixtures place the symbol inside a larger frame precisely because the
    // locator has to find it. If the modal ever drops `locate: true`, the
    // fixtures should be revisited rather than silently passing.
    expect(modalSource).toMatch(/locate:\s*true/);
  });
});
