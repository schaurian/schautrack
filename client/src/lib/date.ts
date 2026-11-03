// Calendar-date helpers. The app's day is a plain "YYYY-MM-DD" string (the
// server's entry_date / todayStr), never an instant. Two stock JS idioms get
// that wrong and only show it away from UTC:
//   - new Date('2026-10-01') parses as UTC midnight, which is Sep 30 in the
//     Americas once formatted in local time;
//   - new Date().toISOString().slice(0, 10) is the UTC date, which is
//     tomorrow in Auckland's morning and yesterday in Los Angeles' evening.

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** True for a bare "YYYY-MM-DD" string (no time, no zone). */
export function isDateOnly(value: string): boolean {
  return DATE_ONLY.test(value);
}

/**
 * Parse "YYYY-MM-DD" as local midnight of that calendar day, so formatting it
 * with the browser's zone shows the same day. Returns an Invalid Date for any
 * other input, like `new Date('garbage')` does.
 */
export function parseLocalDate(ymd: string): Date {
  const m = DATE_ONLY.exec(ymd);
  if (!m) return new Date(Number.NaN);
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
}

/** The browser-local calendar date of `d` as "YYYY-MM-DD". */
export function localDateStr(d: Date = new Date()): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * The dashboard's selected day after the server's "today" moves from
 * `prevToday` to `nextToday` (the tab stayed open across midnight and a
 * refetch brought the new day). A user who was on today stays on today;
 * a user who deliberately picked another day stays there.
 */
export function followToday(selected: string, prevToday: string | undefined, nextToday: string): string {
  if (prevToday && prevToday !== nextToday && selected === prevToday) return nextToday;
  return selected;
}
