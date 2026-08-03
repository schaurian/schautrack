#!/usr/bin/env node
/**
 * Regenerates the barcode PNG fixtures used by tests/barcodeDecode.test.ts.
 *
 *   node scripts/generate-barcode-fixtures.mjs
 *
 * The fixtures are committed, so this script only needs to run when the set of
 * covered symbologies changes. It deliberately uses nothing but Node builtins —
 * a barcode-rendering devDependency would defeat the point of issue #271, which
 * is about *shrinking* the barcode dependency surface.
 *
 * Why the images look the way they do: quagga2 runs with `locate: true` in
 * BarcodeScanModal, which means its patch-based locator has to *find* the
 * barcode inside the frame. A barcode rendered edge-to-edge with no surrounding
 * background is a degenerate input that the locator fails on, so these fixtures
 * place the symbol in the middle of a larger, softly shaded canvas — roughly
 * what a photographed label looks like to the locator.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// EAN/UPC module patterns. R is the bitwise complement of L; G is R reversed.
const L = ['0001101', '0011001', '0010011', '0111101', '0100011',
           '0110001', '0101111', '0111011', '0110111', '0001011'];
const G = ['0100111', '0110011', '0011011', '0100001', '0011101',
           '0111001', '0000101', '0010001', '0001001', '0010111'];
const R = ['1110010', '1100110', '1101100', '1000010', '1011100',
           '1001110', '1010000', '1000100', '1001000', '1110100'];

/** Which of the first six EAN-13 digits use G instead of L, keyed by digit 1. */
const EAN13_PARITY = ['LLLLLL', 'LLGLGG', 'LLGGLG', 'LLGGGL', 'LGLLGG',
                      'LGGLLG', 'LGGGLL', 'LGLGLG', 'LGLGGL', 'LGGLGL'];

/** UPC-E parity for number system 0, keyed by check digit. E = even (G), O = odd (L). */
const UPCE_PARITY = ['EEEOOO', 'EEOEOO', 'EEOOEO', 'EEOOOE', 'EOEEOO',
                     'EOOEEO', 'EOOOEE', 'EOEOEO', 'EOEOOE', 'EOOEOE'];

const toDigits = (s) => [...s].map(Number);

/** Shared UPC/EAN check digit: weights alternate 3,1,3,1... from the right. */
function checkDigit(digits) {
  const sum = digits.reduceRight((acc, d, i, arr) => {
    const fromRight = arr.length - 1 - i;
    return acc + d * (fromRight % 2 === 0 ? 3 : 1);
  }, 0);
  return (10 - (sum % 10)) % 10;
}

function assertCheck(code, payload, expected) {
  const actual = checkDigit(payload);
  if (actual !== expected) {
    throw new Error(`bad check digit for ${code}: expected ${actual}, got ${expected}`);
  }
}

function ean13(code) {
  const d = toDigits(code);
  if (d.length !== 13) throw new Error('EAN-13 needs 13 digits');
  assertCheck(code, d.slice(0, 12), d[12]);
  const parity = EAN13_PARITY[d[0]];
  let bits = '101';
  d.slice(1, 7).forEach((digit, i) => { bits += parity[i] === 'L' ? L[digit] : G[digit]; });
  bits += '01010';
  d.slice(7).forEach((digit) => { bits += R[digit]; });
  return bits + '101';
}

function ean8(code) {
  const d = toDigits(code);
  if (d.length !== 8) throw new Error('EAN-8 needs 8 digits');
  assertCheck(code, d.slice(0, 7), d[7]);
  const left = d.slice(0, 4).map((x) => L[x]).join('');
  const right = d.slice(4).map((x) => R[x]).join('');
  return `101${left}01010${right}101`;
}

function upcA(code) {
  const d = toDigits(code);
  if (d.length !== 12) throw new Error('UPC-A needs 12 digits');
  assertCheck(code, d.slice(0, 11), d[11]);
  const left = d.slice(0, 6).map((x) => L[x]).join('');
  const right = d.slice(6).map((x) => R[x]).join('');
  return `101${left}01010${right}101`;
}

/** Expand `numsys + 6 payload digits + check` to the equivalent 12-digit UPC-A. */
function upcEExpand(code) {
  const d = toDigits(code);
  const [ns, ...rest] = d;
  const x = rest.slice(0, 6);
  const chk = d[7];
  let body;
  if (x[5] <= 2) body = [ns, x[0], x[1], x[5], 0, 0, 0, 0, x[2], x[3], x[4]];
  else if (x[5] === 3) body = [ns, x[0], x[1], x[2], 0, 0, 0, 0, 0, x[3], x[4]];
  else if (x[5] === 4) body = [ns, x[0], x[1], x[2], x[3], 0, 0, 0, 0, 0, x[4]];
  else body = [ns, x[0], x[1], x[2], x[3], x[4], 0, 0, 0, 0, x[5]];
  return [...body, chk];
}

function upcE(code) {
  const d = toDigits(code);
  if (d.length !== 8) throw new Error('UPC-E fixture needs numsys + 6 digits + check');
  const ns = d[0];
  if (ns !== 0 && ns !== 1) throw new Error('UPC-E number system must be 0 or 1');
  const chk = d[7];
  assertCheck(code, upcEExpand(code).slice(0, 11), chk);
  let parity = UPCE_PARITY[chk];
  if (ns === 1) parity = [...parity].map((p) => (p === 'E' ? 'O' : 'E')).join('');
  let bits = '101';
  d.slice(1, 7).forEach((digit, i) => { bits += parity[i] === 'E' ? G[digit] : L[digit]; });
  return bits + '010101'; // UPC-E has no centre guard; it ends with a 6-module guard.
}

const CRC_TABLE = Int32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(tag, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(tag, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/**
 * Render a module bit string as an 8-bit grayscale PNG: the symbol centred on a
 * larger, gently shaded canvas so quagga2's locator has something to locate.
 */
function renderPng(bits, { scale = 4, barHeight = 140, width = 900, height = 700, bg = 200 } = {}) {
  const quiet = new Array(10 * scale).fill(255);
  const strip = [...quiet];
  for (const b of bits) {
    for (let i = 0; i < scale; i++) strip.push(b === '1' ? 0 : 255);
  }
  strip.push(...quiet);
  if (strip.length >= width) throw new Error(`symbol (${strip.length}px) does not fit in ${width}px`);

  const x0 = Math.floor((width - strip.length) / 2);
  const y0 = Math.floor((height - barHeight) / 2);

  // One scanline per row, each prefixed with PNG filter type 0 (None).
  const raw = Buffer.alloc((width + 1) * height);
  let p = 0;
  for (let y = 0; y < height; y++) {
    raw[p++] = 0;
    const shade = bg - Math.floor((y * 20) / height); // subtle top-to-bottom gradient
    raw.fill(shade, p, p + width);
    if (y >= y0 && y < y0 + barHeight) {
      for (let i = 0; i < strip.length; i++) raw[p + x0 + i] = strip[i];
    }
    p += width;
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // colour type: grayscale
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

export const FIXTURES = [
  { file: 'ean13-4006381333931.png', encode: () => ean13('4006381333931') },
  { file: 'ean8-96385074.png', encode: () => ean8('96385074') },
  { file: 'upca-036000291452.png', encode: () => upcA('036000291452') },
  { file: 'upce-04252614.png', encode: () => upcE('04252614') },
  // Negative control: a blank frame must not yield a phantom read.
  { file: 'blank.png', encode: () => '0'.repeat(120) },
];

const outDir = resolve(dirname(fileURLToPath(import.meta.url)), '../tests/fixtures/barcodes');

if (import.meta.url === `file://${process.argv[1]}`) {
  mkdirSync(outDir, { recursive: true });
  for (const { file, encode } of FIXTURES) {
    const png = renderPng(encode());
    writeFileSync(resolve(outDir, file), png);
    console.log(`${file}  ${png.length} bytes`);
  }
}
