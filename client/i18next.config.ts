import { defineConfig } from 'i18next-cli';

// Extracts t('...') / <Trans> keys from the client source into the `en`
// catalogs. Run via `npm run i18n:extract`; `npm run i18n:drift` re-runs it in
// CI mode and fails if the committed catalogs are stale.
//
// Migrated from i18next-parser (deprecated) — see the option map below. Every
// option carried over from `i18next-parser.config.js` is called out so the
// behaviour stays identical:
//
//   locales: ['en']                -> locales: ['en']
//   defaultNamespace: 'common'     -> extract.defaultNS: 'common'
//   input: ['src/**/*.{ts,tsx}']   -> extract.input
//   output: '...$LOCALE/$NAMESPACE.json' -> '...{{language}}/{{namespace}}.json'
//   keySeparator: '.'              -> extract.keySeparator: '.'
//   namespaceSeparator: ':'        -> extract.nsSeparator: ':'
//   sort: true                     -> extract.sort: true
//   keepRemoved: true              -> extract.removeUnusedKeys: false  (CRITICAL:
//                                     i18next-cli DELETES unused keys by default,
//                                     i18next-parser did not. Never flip this on —
//                                     a run must never drop translated strings.)
//   createOldCatalogs: false       -> no equivalent needed; i18next-cli never
//                                     writes `*_old.json` backup catalogs.
export default defineConfig({
  // Extraction only ever writes the source catalog. The other seven locales are
  // translated by hand and guarded by `npm run i18n:check`
  // (scripts/i18n-parity.mjs). Adding them here would make extract seed every
  // locale with empty strings, which would defeat that parity check.
  locales: ['en'],
  extract: {
    input: ['src/**/*.{ts,tsx}'],
    // Test files talk *about* the catalogs; they are not translation sites.
    // `i18n/runtime.test.tsx` holds a probe map and calls t(`${ns}:${KEY[ns]}`),
    // and `i18n/catalogs.test.ts` iterates a `{ ns, key }` case table through
    // `getFixedT(null, ns)`. Up to i18next-cli 1.71 those dynamic forms were
    // simply invisible to the extractor. 1.73 statically evaluates the consts
    // behind them, but cannot pair a key with the namespace it is tested under:
    // the template literal comes out as the cross product of both const lists
    // (every probe key written into all five namespaces), and the `{ count }`
    // cases materialise `_one`/`_other` under the default namespace instead of
    // the one `getFixedT` fixes. Both write keys the app never asks for, so the
    // committed catalogs can never match a fresh extract and `i18n:drift` fails
    // no matter what is committed.
    //
    // Excluding tests is the fix rather than a workaround: extraction should
    // describe what the application asks the runtime for, and every key these
    // files name is either already reached from a real call site or kept by
    // `removeUnusedKeys: false` below.
    ignore: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
    output: 'src/i18n/locales/{{language}}/{{namespace}}.json',
    defaultNS: 'common',
    keySeparator: '.',
    nsSeparator: ':',
    sort: true,
    // Equivalent of i18next-parser's `keepRemoved: true`.
    removeUnusedKeys: false,
    functions: ['t', '*.t'],
    transComponents: ['Trans'],
  },
});
