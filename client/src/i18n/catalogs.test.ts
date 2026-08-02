// Guards the catalog shape against the i18next-parser -> i18next-cli migration.
// The extractor is now stricter about `{ count }` (it emits `_one`/`_other`)
// and about namespace resolution, so these tests pin the two behaviours that
// changed shape but must NOT change what users actually see.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInstance, type i18n } from 'i18next';

const LOCALES_DIR = join(dirname(fileURLToPath(import.meta.url)), 'locales');
const LOCALES = readdirSync(LOCALES_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();
const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'];

/** Mirrors the runtime setup in src/i18n/index.ts (eager resources, ns list). */
function makeI18n(lng: string): i18n {
  const resources: Record<string, Record<string, unknown>> = {};
  for (const ns of NAMESPACES) {
    resources[ns] = JSON.parse(readFileSync(join(LOCALES_DIR, lng, `${ns}.json`), 'utf8'));
  }
  const inst = createInstance();
  inst.init({
    lng,
    resources: { [lng]: resources },
    ns: NAMESPACES,
    defaultNS: 'common',
    interpolation: { escapeValue: false },
  });
  return inst;
}

const DAY_KEYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

describe('namespace-prefixed dynamic day labels', () => {
  // TodoList passes `t` into a helper, so extraction cannot infer the bound
  // namespace; the key carries an explicit `dashboard:` prefix instead. Prove
  // that prefix still resolves to the real translation in every locale.
  it.each(LOCALES)('resolves dashboard:todos.days.* in %s', (lng) => {
    const t = makeI18n(lng).t;
    for (const day of DAY_KEYS) {
      const prefixed = t(`dashboard:todos.days.${day}`);
      expect(prefixed).not.toBe(`dashboard:todos.days.${day}`);
      expect(prefixed).not.toBe(`todos.days.${day}`);
      expect(prefixed.trim()).not.toBe('');
    }
  });

  it('the prefixed key matches the plain lookup inside the dashboard ns', () => {
    const inst = makeI18n('en');
    for (const day of DAY_KEYS) {
      expect(inst.t(`dashboard:todos.days.${day}`)).toBe(
        inst.getFixedT(null, 'dashboard')(`todos.days.${day}`),
      );
    }
  });
});

describe('count-interpolated keys render real text, never a raw key path', () => {
  // These four are called with `{ count }`, so i18next resolves a plural
  // suffix first. The extractor now materialises `_one`/`_other`; if those ever
  // get committed as key-path placeholders the UI would show e.g.
  // "passkey.countUsed" verbatim. Catch that here.
  const CASES: Array<{ ns: string; key: string }> = [
    { ns: 'dashboard', key: 'savedFoods.logQuantityButton' },
    { ns: 'settings', key: 'admin.usersHeading' },
    { ns: 'settings', key: 'passkey.countUsed' },
    { ns: 'settings', key: 'savedFoods.description' },
  ];

  it.each(LOCALES)('renders sane plural forms in %s', (lng) => {
    const inst = makeI18n(lng);
    for (const { ns, key } of CASES) {
      const t = inst.getFixedT(null, ns);
      for (const count of [0, 1, 2, 5, 22]) {
        const out = t(key, { count });
        expect(out).not.toBe(key);
        expect(out).not.toContain('{{count}}');
        expect(out).toContain(String(count));
      }
    }
  });
});

describe('optional admin section descriptions stay falsy', () => {
  // Admin.tsx does `t(key, { defaultValue: '' }) || undefined`. Sections with
  // no description must resolve to '' so nothing is rendered — an extracted
  // key-path placeholder would be truthy and leak into the UI.
  const WITHOUT_DESCRIPTION = ['features', 'general', 'legal', 'security', 'seo'];

  it.each(LOCALES)('resolves empty descriptions to falsy in %s', (lng) => {
    const t = makeI18n(lng).getFixedT(null, 'settings');
    for (const section of WITHOUT_DESCRIPTION) {
      const key = `admin.sections.${section}.description`;
      expect(t(key, { defaultValue: '' }) || undefined).toBeUndefined();
    }
  });

  it.each(LOCALES)('still resolves the sections that do have text in %s', (lng) => {
    const t = makeI18n(lng).getFixedT(null, 'settings');
    for (const section of ['ai', 'oidc', 'passkeys', 'smtp']) {
      const value = t(`admin.sections.${section}.description`, { defaultValue: '' });
      expect(value.trim()).not.toBe('');
    }
  });
});
