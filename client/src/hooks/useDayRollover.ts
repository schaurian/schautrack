import { useEffect, useRef } from 'react';
import { nextMidnightInTz } from '@/lib/date';

/**
 * Past the server's midnight by this much before re-checking, so a client
 * clock a little ahead of the server's still sees the new day.
 */
export const DAY_ROLLOVER_BUFFER_MS = 5_000;

/**
 * Calls `onRollover` just after each local midnight in `timeZone` (the user's
 * stored zone, not the browser's), for as long as the component is mounted.
 * The timer is re-armed after each firing and cleared on unmount or when the
 * zone changes.
 *
 * Without it the dashboard only noticed a new day on a refetch (window focus,
 * SSE): a tab left visible across 00:00 kept filing entries under yesterday.
 */
export function useDayRollover(timeZone: string | undefined, onRollover: () => void): void {
  const callback = useRef(onRollover);
  useEffect(() => {
    callback.current = onRollover;
  }, [onRollover]);

  useEffect(() => {
    if (!timeZone) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const schedule = () => {
      const now = Date.now();
      const delay = Math.max(0, nextMidnightInTz(timeZone, now) - now) + DAY_ROLLOVER_BUFFER_MS;
      timer = setTimeout(() => {
        callback.current();
        schedule();
      }, delay);
    };
    schedule();
    return () => clearTimeout(timer);
  }, [timeZone]);
}
