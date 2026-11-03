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

/**
 * Today's calendar date in an IANA zone (the user's stored zone), as
 * "YYYY-MM-DD". An unknown zone falls back to the browser's local date rather
 * than throwing, like the server falls back to UTC.
 */
export function todayInTz(timeZone: string | undefined, now: Date = new Date()): string {
  if (timeZone) {
    try {
      return now.toLocaleDateString('en-CA', { timeZone });
    } catch {
      // RangeError: unknown zone — fall through.
    }
  }
  return localDateStr(now);
}

/** UTC offset of `timeZone` at instant `t`, in ms (wall clock minus UTC). */
function tzOffsetMs(timeZone: string, t: number): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(t));
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value);
  const wallAsUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'));
  return wallAsUtc - Math.floor(t / 1000) * 1000;
}

/**
 * The instant (epoch ms) at which the calendar date in `timeZone` next
 * changes, i.e. the coming local midnight. DST-aware: the offset is taken at
 * the target, not at `now`, so a 23- or 25-hour day lands on 00:00. In the
 * few zones whose DST jump skips midnight itself, it returns the jump instant
 * (the first moment of the new day). An unknown zone uses the browser's.
 */
export function nextMidnightInTz(timeZone: string | undefined, now: number = Date.now()): number {
  if (!timeZone || !isValidZone(timeZone)) {
    const local = new Date(now);
    return new Date(local.getFullYear(), local.getMonth(), local.getDate() + 1).getTime();
  }
  const today = todayInTz(timeZone, new Date(now));
  const [y, m, d] = today.split('-').map(Number);
  const wallMidnight = Date.UTC(y, m - 1, d + 1);
  const first = wallMidnight - tzOffsetMs(timeZone, now);
  const refined = wallMidnight - tzOffsetMs(timeZone, first);
  return todayInTz(timeZone, new Date(refined)) !== today ? refined : first;
}

function isValidZone(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
    return true;
  } catch {
    return false;
  }
}
