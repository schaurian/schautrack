// Extracts t('...') / <Trans> keys from the client source into the `en`
// catalogs. Run via `npm run i18n:extract`. Existing keys are preserved
// (keepRemoved) so a run never deletes translated strings; it only surfaces
// NEW literals that were added without a key.
export default {
  locales: ['en'],
  defaultNamespace: 'common',
  input: ['src/**/*.{ts,tsx}'],
  output: 'src/i18n/locales/$LOCALE/$NAMESPACE.json',
  keySeparator: '.',
  namespaceSeparator: ':',
  sort: true,
  keepRemoved: true,
  createOldCatalogs: false,
};
