import i18n, { type BackendModule, type ReadCallback } from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import enAuth from './locales/en/auth.json';
import enCommon from './locales/en/common.json';
import enDashboard from './locales/en/dashboard.json';
import enLanding from './locales/en/landing.json';
import enSettings from './locales/en/settings.json';

// Endonyms shown in the language dropdown. `en` first, rest alphabetized by endonym.
export const SUPPORTED_LANGUAGES: { code: string; endonym: string }[] = [
  { code: 'en', endonym: 'English' },
  { code: 'de', endonym: 'Deutsch' },
  { code: 'es', endonym: 'Español' },
  { code: 'fr', endonym: 'Français' },
  { code: 'it', endonym: 'Italiano' },
  { code: 'nl', endonym: 'Nederlands' },
  { code: 'pl', endonym: 'Polski' },
  { code: 'pt', endonym: 'Português' },
];

const SUPPORTED_CODES = SUPPORTED_LANGUAGES.map((l) => l.code);
export function isSupportedLanguage(code: string): boolean {
  return SUPPORTED_CODES.includes(code);
}

type Catalog = Record<string, unknown>;
type CatalogModule = { default: Catalog };

/** The namespaces every locale ships. Exported so tests assert against one list. */
export const NAMESPACES = ['common', 'auth', 'dashboard', 'settings', 'landing'] as const;

/**
 * English stays in the startup bundle, statically imported, and is never fetched.
 * It is the fallback language: any key a deferred catalog is missing resolves
 * against it, so a lazily-loaded English would render raw key paths on a miss.
 */
const ENGLISH_CATALOGS: Record<string, Catalog> = {
  auth: enAuth,
  common: enCommon,
  dashboard: enDashboard,
  landing: enLanding,
  settings: enSettings,
};

/**
 * Every other catalog is a Vite-managed dynamic import, so it is requested only
 * for the detected language or after the user changes their language preference.
 *
 * English is excluded from the glob deliberately. Globbing it too made Rollup
 * see the same module both statically (the imports above) and dynamically, which
 * it reports as INEFFECTIVE_DYNAMIC_IMPORT and resolves by keeping the module in
 * the entry chunk — the dynamic half was dead weight. `read()` serves English
 * from the bundled map instead, so the backend still answers for every language.
 */
const catalogLoaders = import.meta.glob<CatalogModule>([
  './locales/*/*.json',
  '!./locales/en/*.json',
]);

const catalogBackend: BackendModule = {
  type: 'backend',
  init() {},
  read(language: string, namespace: string, callback: ReadCallback) {
    const bundled = language === 'en' ? ENGLISH_CATALOGS[namespace] : undefined;
    if (bundled) {
      callback(null, bundled);
      return;
    }

    const loader = catalogLoaders[`./locales/${language}/${namespace}.json`];
    if (!loader) {
      callback(new Error(`No translation catalog for ${language}/${namespace}`), false);
      return;
    }

    void loader().then(
      (module) => callback(null, module.default),
      (error: unknown) => callback(error instanceof Error ? error : String(error), false),
    );
  },
};

export const i18nReady = i18n
  .use(catalogBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    // Tell i18next that English is only the bundled subset; without this it
    // assumes every language is already present and never calls the backend.
    partialBundledLanguages: true,
    resources: { en: ENGLISH_CATALOGS },
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_CODES,
    nonExplicitSupportedLngs: true, // 'de-DE' -> 'de'
    load: 'languageOnly',
    ns: [...NAMESPACES],
    defaultNS: 'common',
    interpolation: { escapeValue: false }, // React already escapes
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
      lookupLocalStorage: 'i18nextLng',
    },
    returnNull: false,
  })
  // A failed deferred catalog must not leave the application blank: English is
  // already present and remains the documented fallback language.
  .catch(async () => i18n.changeLanguage('en'));

// Keep <html lang> in sync for screen readers / SEO. Guarded so the module
// is import-safe in the DOM-less (node) test environment.
if (typeof document !== 'undefined') {
  const applyHtmlLang = (lng: string) => {
    document.documentElement.lang = lng.split('-')[0];
  };
  applyHtmlLang(i18n.language || 'en');
  i18n.on('languageChanged', applyHtmlLang);
}

export default i18n;
