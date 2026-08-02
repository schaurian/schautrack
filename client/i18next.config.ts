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
