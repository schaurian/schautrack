import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Runtime coverage for deferred translation catalogs (issue #485).
 *
 * `tests/i18nBundleSplit.test.ts` proves the build half — that only English
 * rides in the entry chunk. This file proves the runtime half: that a deferred
 * catalog still arrives complete, and still *renders*, for a returning user's
 * stored language and for every language the selector offers.
 *
 * Catalogs are read here with an eager `import.meta.glob` on purpose: this is a
 * test module, outside the application's entry graph, so it never reaches the
 * shipped bundle. Comparing the loaded resource bundle against the file on disk
 * is what makes "the complete catalog" an assertion rather than a hope.
 */

type Catalog = Record<string, unknown>;

const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'] as const;
const DEFERRED_LANGUAGES = ['de', 'es', 'fr', 'it', 'nl', 'pl', 'pt'];

/**
 * One key per namespace, each translated differently from English in all eight
 * locales. Rendering only `common` would let a half-fetched language pass.
 */
const PROBE_KEYS: Record<(typeof NAMESPACES)[number], string> = {
  common: 'app.loading',
  auth: 'deleteAccount.couldNotDelete',
  dashboard: 'aiPhoto.analyzingText',
  landing: 'features.aiEstimation.title',
  settings: 'account.logout',
};

const catalogModules = import.meta.glob<{ default: Catalog }>('./locales/*/*.json', {
  eager: true,
});
const catalogs: Record<string, Record<string, Catalog>> = {};
for (const path in catalogModules) {
  const match = /\.\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  if (!match) continue;
  (catalogs[match[1]] ??= {})[match[2]] = catalogModules[path].default;
}

let releaseDom: (() => void) | undefined;

/**
 * Boot the real i18n module from a clean slate, as a page load would.
 *
 * Everything React touches is imported *after* `vi.resetModules()` and in one
 * batch. The reset gives the re-imported i18n module a fresh copy of
 * react-i18next, and a hook from one copy of React cannot run inside a tree
 * rendered by another — the dispatcher is per-copy. Importing react and Testing
 * Library alongside keeps the whole render in a single module registry.
 */
async function freshRuntime(storedLanguage?: string) {
  localStorage.clear();
  if (storedLanguage) localStorage.setItem('i18nextLng', storedLanguage);
  vi.resetModules();

  const [i18nModule, reactI18next, react, testing] = await Promise.all([
    import('./index'),
    import('react-i18next'),
    import('react'),
    import('@testing-library/react'),
  ]);

  await i18nModule.i18nReady;
  releaseDom = testing.cleanup;
  const namespaces: readonly string[] = i18nModule.NAMESPACES;

  const i18n = i18nModule.default;

  /** Every paint of the probe, oldest first, as ns -> rendered text. */
  const painted: Record<string, string>[] = [];

  function Probe() {
    const { t } = reactI18next.useTranslation([...NAMESPACES]);
    const snapshot: Record<string, string> = {};
    for (const ns of NAMESPACES) snapshot[ns] = t(`${ns}:${PROBE_KEYS[ns]}`);
    painted.push(snapshot);

    return react.createElement(
      'div',
      null,
      NAMESPACES.map((ns) =>
        react.createElement('span', { key: ns, 'data-testid': ns }, snapshot[ns])
      )
    );
  }

  const rendered = testing.render(react.createElement(Probe));
  const read = (ns: string) => rendered.getByTestId(ns).textContent ?? '';
  const changeLanguage = async (lng: string) => {
    await testing.act(async () => {
      await i18n.changeLanguage(lng);
    });
  };

  return { i18n, namespaces, painted, read, changeLanguage };
}

afterEach(() => {
  releaseDom?.();
  releaseDom = undefined;
  localStorage.clear();
  vi.resetModules();
});

/** Asserts the DOM shows `lng`'s own catalog text, not English and not a key. */
function expectRenderedLanguage(
  i18n: { getResource: (l: string, n: string, k: string) => unknown },
  read: (ns: string) => string,
  lng: string
) {
  for (const ns of NAMESPACES) {
    const key = PROBE_KEYS[ns];
    const expected = i18n.getResource(lng, ns, key) as string;
    expect(expected, `fixture: ${lng}/${ns}:${key} must exist`).toBeTruthy();

    const shown = read(ns);
    expect(shown, `${lng} ${ns} renders its own catalog`).toBe(expected);
    expect(shown, `${lng} ${ns} is not the English fallback`).not.toBe(
      i18n.getResource('en', ns, key) as string
    );
    expect(shown, `${lng} ${ns} is not a raw key path`).not.toContain(key);
  }
}

describe('a returning user with a stored language', () => {
  it('loads every namespace of that language before the first render', async () => {
    const { i18n, namespaces } = await freshRuntime('de-DE');

    // The probes below only cover a namespace this list names, so a sixth one
    // added to src/i18n/index.ts must show up here too.
    expect([...namespaces]).toEqual([...NAMESPACES]);
    expect(i18n.resolvedLanguage).toBe('de');
    expect(document.documentElement.lang).toBe('de');
    for (const namespace of NAMESPACES) {
      expect(i18n.hasResourceBundle('de', namespace)).toBe(true);
    }
    expect(i18n.t('app.loading')).toBe('Lädt...');
  });

  it('paints that language on the very first frame, never English first', async () => {
    const { i18n, painted, read } = await freshRuntime('de-DE');

    // The regression this guards is a flash of English: the app mounting
    // before the stored language's catalogs have arrived. Assert on the first
    // recorded paint, not just the settled DOM, so a later correction cannot
    // hide it.
    expect(painted.length).toBeGreaterThan(0);
    expect(painted[0].common).toBe('Lädt...');
    for (const snapshot of painted) {
      expect(snapshot.common).not.toBe(i18n.getResource('en', 'common', 'app.loading'));
    }
    expectRenderedLanguage(i18n, read, 'de');
  });
});

describe('switching language', () => {
  it('fetches, renders and completes the catalog for every supported language', async () => {
    const { i18n, read, changeLanguage } = await freshRuntime('en');

    for (const language of DEFERRED_LANGUAGES) {
      expect(
        i18n.hasResourceBundle(language, 'common'),
        `${language} must not be bundled up front`
      ).toBe(false);

      await changeLanguage(language);

      expect(i18n.resolvedLanguage).toBe(language);
      expect(document.documentElement.lang).toBe(language);

      for (const namespace of NAMESPACES) {
        expect(i18n.hasResourceBundle(language, namespace)).toBe(true);
        // Not a subset, not a truncated fetch: the whole file, key for key.
        expect(i18n.getResourceBundle(language, namespace)).toEqual(
          catalogs[language][namespace]
        );
      }

      expectRenderedLanguage(i18n, read, language);
    }
  });

  it('falls back to English text when a catalog fails to load', async () => {
    const { i18n, read, changeLanguage } = await freshRuntime('en');

    // Simulate the deferred chunk 404ing — a stale index.html after a deploy,
    // or an offline client. English is bundled, so the UI must stay readable
    // rather than render key paths.
    const failing = 'fr';
    i18n.services.backendConnector.backend.read = (
      _lng: string,
      _ns: string,
      callback: (err: unknown, data: false | Catalog) => void
    ) => {
      callback(new Error('chunk unavailable'), false);
    };

    await changeLanguage(failing);

    for (const ns of NAMESPACES) {
      const key = PROBE_KEYS[ns];
      expect(read(ns)).toBe(i18n.getResource('en', ns, key) as string);
    }
  });
});
