import i18n from '@/i18n';

/** The active UI locale (falls back to 'en'). */
export function activeLocale(): string {
  return i18n.language || 'en';
}

export function formatDate(
  value: string | number | Date,
  locale: string = activeLocale(),
  opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' },
): string {
  const d = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat(locale, opts).format(d);
}

export function formatTime(
  value: string | number | Date,
  locale: string = activeLocale(),
  opts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' },
): string {
  const d = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat(locale, opts).format(d);
}

export function formatNumber(
  value: number,
  locale: string = activeLocale(),
  opts?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(locale, opts).format(value);
}
