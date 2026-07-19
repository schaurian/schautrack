#!/usr/bin/env node
// Fails (exit 1) if any non-`en` locale is missing a key present in `en`.
// A missing key would silently fall back to English at runtime, so this is
// the guardrail that keeps translations complete as the source catalog grows.
//
// Plural note: locales may legitimately have MORE keys than `en` (e.g. Polish
// expands `_one`/`_other` into `_one`/`_few`/`_many`/`_other`). Extra keys are
// fine; only keys present in `en` but absent from a locale are failures.

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOCALES_DIR = join(__dirname, '..', 'src', 'i18n', 'locales');
const SOURCE = 'en';

/** Flatten nested object into dot-joined leaf key paths. */
function flatten(obj, prefix = '', out = new Set()) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v, key, out);
    } else {
      out.add(key);
    }
  }
  return out;
}

/** Union of all leaf keys across every namespace file for a locale. */
function localeKeys(locale) {
  const dir = join(LOCALES_DIR, locale);
  const keys = new Set();
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    const ns = file.replace(/\.json$/, '');
    const obj = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    for (const k of flatten(obj)) keys.add(`${ns}:${k}`);
  }
  return keys;
}

const locales = readdirSync(LOCALES_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

const sourceKeys = localeKeys(SOURCE);
let failed = false;

for (const locale of locales) {
  if (locale === SOURCE) continue;
  const keys = localeKeys(locale);
  const missing = [...sourceKeys].filter((k) => !keys.has(k)).sort();
  if (missing.length) {
    failed = true;
    console.error(`\n✗ ${locale}: missing ${missing.length} key(s) present in ${SOURCE}:`);
    for (const k of missing.slice(0, 40)) console.error(`    ${k}`);
    if (missing.length > 40) console.error(`    ... and ${missing.length - 40} more`);
  } else {
    console.log(`✓ ${locale}: ${keys.size} keys (parity with ${SOURCE}: ${sourceKeys.size})`);
  }
}

if (failed) {
  console.error('\ni18n parity check FAILED — translate the missing keys.');
  process.exit(1);
}
console.log('\ni18n parity check passed.');
