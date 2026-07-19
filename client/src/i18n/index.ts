import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

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

// Eagerly load every locale/namespace JSON so adding a file needs no wiring here.
const modules = import.meta.glob('./locales/*/*.json', { eager: true }) as Record<
  string,
  { default: Record<string, unknown> }
>;
const resources: Record<string, Record<string, Record<string, unknown>>> = {};
for (const path in modules) {
  const match = path.match(/\.\/locales\/([^/]+)\/([^/]+)\.json$/);
  if (!match) continue;
  const [, lng, ns] = match;
  (resources[lng] ??= {})[ns] = modules[path].default;
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_CODES,
    nonExplicitSupportedLngs: true, // 'de-DE' -> 'de'
    load: 'languageOnly',
    ns: ['common', 'auth', 'dashboard', 'settings', 'landing'],
    defaultNS: 'common',
    interpolation: { escapeValue: false }, // React already escapes
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
      lookupLocalStorage: 'i18nextLng',
    },
    returnNull: false,
  });

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
