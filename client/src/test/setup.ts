import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeAll } from 'vitest';
import i18n from '@/i18n';

// Import the real i18n instance rather than stubbing useTranslation. Without
// it react-i18next warns NO_I18NEXT_INSTANCE and t() returns the key itself,
// so a query for /decrease/i matches the string "quantityStepper.decrease" and
// the test passes without ever proving the label is translated — or that the
// key exists in the catalog at all. With the real instance, a key deleted from
// common.json fails the component test that depends on it.
beforeAll(async () => {
  // Pin English: the language detector otherwise reads the environment, and a
  // machine set to German would render German copy into assertions written
  // against English.
  await i18n.changeLanguage('en');
});

// Vitest's `globals: true` gives Testing Library its automatic cleanup, but
// only for the default export path. Registering it explicitly means a
// component left mounted by one test cannot leak into the DOM the next one
// queries — the usual cause of a test that passes alone and fails in a suite.
afterEach(cleanup);
