import i18n from '@/i18n';
import { isDateOnly, parseLocalDate } from './date';

/** The active UI locale (falls back to 'en'). */
export function activeLocale(): string {
  return i18n.language || 'en';
}

export function formatDate(
  value: string | number | Date,
  locale: string = activeLocale(),
  opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' },
): string {
  // A bare "YYYY-MM-DD" is a calendar day, not an instant: new Date() would
  // read it as UTC midnight and show the previous day west of UTC.
  const d = value instanceof Date
    ? value
    : typeof value === 'string' && isDateOnly(value) ? parseLocalDate(value) : new Date(value);
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
 *
 * numeric:'always' on purpose: 'auto' names calendar units ("yesterday",
 * "vorgestern", "last month"), which reads oddly for elapsed time after a
 * label like "Last login". A time in the future can only be clock skew, so it
 * and anything under half a second read as the locale's "now".
 */
export function formatRelativeTime(
  value: string | number | Date,
  now: Date = new Date(),
  locale: string = activeLocale(),
): string {
  const d = value instanceof Date ? value : new Date(value);
  // Seconds elapsed, as a positive magnitude so .5 rounds up either way.
  let amount = (now.getTime() - d.getTime()) / 1000;
  if (Math.round(amount) <= 0) return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(0, 'second');
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'always' });
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.round(amount) < size) return rtf.format(-Math.round(amount), unit);
    amount /= size;
  }
  return rtf.format(-Math.round(amount), 'year');
}
