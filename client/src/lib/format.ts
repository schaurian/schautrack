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

const RELATIVE_STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['second', 60],
  ['minute', 60],
  ['hour', 24],
  ['day', 30],
  ['month', 12],
  ['year', Number.POSITIVE_INFINITY],
];

/**
 * "3 days ago" / "vor 3 Tagen" — the past (or future) distance from `now`,
 * in the largest unit that keeps the number above one, via the locale's own
 * Intl.RelativeTimeFormat. Months are 30 days and years 12 of those: this is
 * for at-a-glance recency, the exact timestamp belongs in a tooltip.
 */
export function formatRelativeTime(
  value: string | number | Date,
  now: Date = new Date(),
  locale: string = activeLocale(),
): string {
  const d = value instanceof Date ? value : new Date(value);
  let amount = (d.getTime() - now.getTime()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(Math.round(amount)) < size) return rtf.format(Math.round(amount), unit);
    amount /= size;
  }
  return rtf.format(Math.round(amount), 'year');
}
