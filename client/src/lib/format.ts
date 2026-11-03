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

/**
 * Fixed-precision decimal in the active locale — `82.5` in English, `82,5` in
 * German. The read-only replacement for `n.toFixed(digits)`, which always
 * prints a period whatever the UI language. Not for values seeded into an
 * editable input: those are parsed back as JavaScript numbers.
 */
export function formatDecimal(value: number, digits = 1, locale: string = activeLocale()): string {
  return formatNumber(value, locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
    useGrouping: false,
  });
}

/**
 * The two date styles the app shows a calendar day in, so every surface that
 * names a day reads the same way in a given language:
 *
 * - `short` — the day you are looking at, year implied: "Tue, Nov 3" / "Di., 3. Nov."
 *   (the dashboard date pill and the entries header).
 * - `long`  — a day that may be in another year: "Nov 3, 2026" / "3. Nov. 2026"
 *   (plan target and projected dates, chart axis, measurement dates).
 */
export const DAY_STYLES = {
  short: { weekday: 'short', month: 'short', day: 'numeric' },
  long: { year: 'numeric', month: 'short', day: 'numeric' },
} as const satisfies Record<string, Intl.DateTimeFormatOptions>;

export type DayStyle = keyof typeof DAY_STYLES;

/**
 * Format a calendar day ("YYYY-MM-DD", which has no time zone) in the active
 * locale. Parsed as a local date on purpose: `new Date('2026-11-03')` is UTC
 * midnight, which renders as Nov 2 anywhere west of Greenwich. Anything that
 * is not a bare day is returned unchanged rather than rendered as "Invalid Date".
 */
export function formatDay(day: string, style: DayStyle = 'long', locale: string = activeLocale()): string {
  if (!isDateOnly(day)) return day;
  return new Intl.DateTimeFormat(locale, DAY_STYLES[style]).format(parseLocalDate(day));
}
