// Guards the catalog shape against the i18next-parser -> i18next-cli migration.
// The extractor is now stricter about `{ count }` (it emits `_one`/`_other`)
// and about namespace resolution, so these tests pin the two behaviours that
// changed shape but must NOT change what users actually see.
//
// Catalogs are loaded with the same `import.meta.glob` call src/i18n/index.ts
// uses, deliberately: it keeps this file free of `node:fs` (the client has no
// @types/node, and adding it would leak Node globals into a browser app's type
// surface) and it exercises the very loading path production runs through.
import { describe, it, expect } from 'vitest';
import { createInstance, type i18n } from 'i18next';

type Catalog = Record<string, unknown>;

const modules = import.meta.glob('./locales/*/*.json', { eager: true });

const catalogs: Record<string, Record<string, Catalog>> = {};
for (const path in modules) {
  const match = /\.\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  if (!match) continue;
  const [, lng, ns] = match;
  (catalogs[lng] ??= {})[ns] = (modules[path] as { default: Catalog }).default;
}

const LOCALES = Object.keys(catalogs).sort();
const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'];

/** Mirrors the runtime setup in src/i18n/index.ts (eager resources, ns list). */
function makeI18n(lng: string): i18n {
  const inst = createInstance();
  inst.init({
    lng,
    resources: { [lng]: catalogs[lng] },
    ns: NAMESPACES,
    defaultNS: 'common',
    interpolation: { escapeValue: false },
  });
  return inst;
}

const DAY_KEYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

// Sanity: if the glob ever silently matched nothing, every assertion below
// would vacuously pass. Fail loudly instead.
describe('catalog fixtures', () => {
  it('loads all eight locales with every namespace', () => {
    expect(LOCALES).toEqual(['de', 'en', 'es', 'fr', 'it', 'nl', 'pl', 'pt']);
    for (const lng of LOCALES) {
      expect(Object.keys(catalogs[lng]).sort()).toEqual([...NAMESPACES].sort());
    }
  });
});

describe('namespace-prefixed dynamic day labels', () => {
  // TodoList passes `t` into a helper, so extraction cannot infer the bound
  // namespace; the key carries an explicit `dashboard:` prefix instead. Prove
  // that prefix still resolves to the real translation in every locale.
  for (const lng of LOCALES) {
    it(`resolves dashboard:todos.days.* in ${lng}`, () => {
      const inst = makeI18n(lng);
      for (const day of DAY_KEYS) {
        const prefixed = inst.t(`dashboard:todos.days.${day}`);
        expect(prefixed).not.toBe(`dashboard:todos.days.${day}`);
        expect(prefixed).not.toBe(`todos.days.${day}`);
        expect(prefixed.trim()).not.toBe('');
      }
    });
  }

  it('the prefixed key matches the plain lookup inside the dashboard ns', () => {
    const inst = makeI18n('en');
    const dashboardT = inst.getFixedT(null, 'dashboard');
    for (const day of DAY_KEYS) {
      expect(inst.t(`dashboard:todos.days.${day}`)).toBe(dashboardT(`todos.days.${day}`));
    }
  });
});

describe('count-interpolated keys render real text, never a raw key path', () => {
  // These four are called with `{ count }`, so i18next resolves a plural
  // suffix first. The extractor now materialises `_one`/`_other`; if those ever
  // get committed as key-path placeholders the UI would show e.g.
  // "passkey.countUsed" verbatim. Catch that here.
  const CASES: { ns: string; key: string }[] = [
    { ns: 'dashboard', key: 'savedFoods.logQuantityButton' },
    { ns: 'settings', key: 'admin.usersHeading' },
    { ns: 'settings', key: 'passkey.countUsed' },
    { ns: 'settings', key: 'savedFoods.description' },
  ];

  for (const lng of LOCALES) {
    it(`renders sane plural forms in ${lng}`, () => {
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
  }
});

describe('optional admin section descriptions stay falsy', () => {
  // Admin.tsx does `t(key, { defaultValue: '' }) || undefined`. Sections with
  // no description must resolve to '' so nothing is rendered — an extracted
  // key-path placeholder would be truthy and leak into the UI.
  const WITHOUT_DESCRIPTION = ['features', 'general', 'legal', 'security', 'seo'];
  const WITH_DESCRIPTION = ['ai', 'oidc', 'passkeys', 'smtp'];

  for (const lng of LOCALES) {
    it(`resolves empty descriptions to falsy in ${lng}`, () => {
      const t = makeI18n(lng).getFixedT(null, 'settings');
      for (const section of WITHOUT_DESCRIPTION) {
        const key = `admin.sections.${section}.description`;
        expect(t(key, { defaultValue: '' }) || undefined).toBeUndefined();
      }
    });

    it(`still resolves the sections that do have text in ${lng}`, () => {
      const t = makeI18n(lng).getFixedT(null, 'settings');
      for (const section of WITH_DESCRIPTION) {
        const value = t(`admin.sections.${section}.description`, { defaultValue: '' });
        expect(value.trim()).not.toBe('');
      }
    });
  }
});

describe('energy unit', () => {
  // Entries, goals and the plan all say "kcal"; a bare "cal" (barcode results
  // once did) reads as a different, 1000x smaller unit.
  const leaves = (obj: unknown, path: string[] = []): [string, string][] =>
    obj && typeof obj === 'object'
      ? Object.entries(obj).flatMap(([k, v]) => leaves(v, [...path, k]))
      : typeof obj === 'string' ? [[path.join('.'), obj]] : [];

  it.each(LOCALES)('%s never labels energy as bare "cal"', (lng) => {
    const offenders = leaves(catalogs[lng]).filter(([, v]) => /(^|[\s}])cal(?![\p{L}\p{N}])/u.test(v));
    expect(offenders).toEqual([]);
  });
});

// The ring's "+N over" (dashboard today.over) and the tooltip on the same ring
// (common macros.over, via computeMacroStatus) describe one number, so they
// must use one word. German once read "+100 drüber" on the ring and "100 über"
// in its tooltip; Italian and Polish had the same split.
describe('ring overshoot wording', () => {
  it.each(LOCALES)('%s: ring text is the tooltip text with a leading +', (lng) => {
    const inst = makeI18n(lng);
    const ring = inst.t('today.over', { ns: 'dashboard', amount: 100 });
    const tooltip = inst.t('macros.over', { ns: 'common', amount: 100 });
    expect(ring).toBe(`+${tooltip}`);
  });
});

// The calendar day-dot explains an amber/red dot with the same word the ring
// uses: German said "drüber" there too.
describe('day-dot reason wording', () => {
  it('de: over reason says "über", like the ring', () => {
    const inst = makeI18n('de');
    expect(inst.t('dayDot.reason.over', { ns: 'dashboard', metric: 'Protein', pct: 12 })).toBe('Protein 12 % über');
  });
});

// German shipped the English "Todos" as the section title. The feature is
// "Aufgaben" in German; no German string may show the English word.
describe('German todo wording', () => {
  it('uses Aufgabe/Aufgaben, never the English Todo', () => {
    const offenders: string[] = [];
    const walk = (node: unknown, path: string) => {
      if (typeof node === 'string') {
        if (/\bTodos?\b|Todo-/.test(node)) offenders.push(`${path}: ${node}`);
      } else if (node && typeof node === 'object') {
        for (const [k, v] of Object.entries(node)) walk(v, path ? `${path}.${k}` : k);
      }
    };
    for (const ns of NAMESPACES) walk(catalogs.de[ns], ns);
    expect(offenders).toEqual([]);
    expect(makeI18n('de').t('todos.sectionTitle', { ns: 'dashboard' })).toBe('Aufgaben');
  });
});
