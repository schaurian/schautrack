import { afterEach, describe, expect, it, vi } from 'vitest';

const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'];
const DEFERRED_LANGUAGES = ['de', 'es', 'fr', 'it', 'nl', 'pl', 'pt'];

async function freshI18n(storedLanguage?: string) {
  localStorage.clear();
  if (storedLanguage) localStorage.setItem('i18nextLng', storedLanguage);
  vi.resetModules();

  const module = await import('./index');
  await module.i18nReady;
  return module.default;
}

afterEach(() => {
  localStorage.clear();
  vi.resetModules();
});

describe('deferred catalog loading', () => {
  it('loads a stored language and all its namespaces before the first render', async () => {
    const i18n = await freshI18n('de-DE');

    expect(i18n.resolvedLanguage).toBe('de');
    expect(document.documentElement.lang).toBe('de');
    for (const namespace of NAMESPACES) {
      expect(i18n.hasResourceBundle('de', namespace)).toBe(true);
    }
    expect(i18n.t('app.loading')).toBe('Lädt...');
  });

  it('fetches every supported language catalog when it is selected', async () => {
    const i18n = await freshI18n('en');

    for (const language of DEFERRED_LANGUAGES) {
      expect(i18n.hasResourceBundle(language, 'common')).toBe(false);

      await i18n.changeLanguage(language);

      expect(i18n.resolvedLanguage).toBe(language);
      for (const namespace of NAMESPACES) {
        expect(i18n.hasResourceBundle(language, namespace)).toBe(true);
      }
      expect(i18n.t('app.loading')).not.toBe('app.loading');
    }
  });
});
