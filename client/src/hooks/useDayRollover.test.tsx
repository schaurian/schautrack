import { renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DAY_ROLLOVER_BUFFER_MS, useDayRollover } from './useDayRollover';

// The browser zone is deliberately different from the user's stored zone:
// the rollover must follow the stored one.
const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
const originalTz = env.TZ;

beforeEach(() => {
  env.TZ = 'America/Los_Angeles';
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  env.TZ = originalTz;
});

describe('useDayRollover', () => {
  it('fires just after midnight in the stored zone, then re-arms for the next one', () => {
    // 23:59:00 on Nov 3 in Auckland (NZDT, UTC+13).
    vi.setSystemTime(new Date('2026-11-03T10:59:00Z'));
    const onRollover = vi.fn();
    renderHook(() => useDayRollover('Pacific/Auckland', onRollover));

    vi.advanceTimersByTime(60_000 + DAY_ROLLOVER_BUFFER_MS - 1);
    expect(onRollover).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onRollover).toHaveBeenCalledTimes(1);

    // Next midnight is 24 h later; nothing in between.
    vi.advanceTimersByTime(24 * 3600_000 - 1);
    expect(onRollover).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    expect(onRollover).toHaveBeenCalledTimes(2);
  });

  it('lands on 00:00 across a DST change (Berlin 25-hour day)', () => {
    // 2026-10-25 00:30 CEST in Berlin; clocks fall back at 03:00, so the next
    // midnight is 24.5 h of real time away, not 23.5 h.
    vi.setSystemTime(new Date('2026-10-24T22:30:00Z'));
    const onRollover = vi.fn();
    renderHook(() => useDayRollover('Europe/Berlin', onRollover));

    vi.advanceTimersByTime(24.5 * 3600_000 + DAY_ROLLOVER_BUFFER_MS - 1);
    expect(onRollover).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onRollover).toHaveBeenCalledTimes(1);
  });

  it('lands on 00:00 across spring-forward (Berlin 23-hour day)', () => {
    // 2026-03-29 00:30 CET; clocks jump at 02:00, next midnight is 22.5 h away.
    vi.setSystemTime(new Date('2026-03-28T23:30:00Z'));
    const onRollover = vi.fn();
    renderHook(() => useDayRollover('Europe/Berlin', onRollover));

    vi.advanceTimersByTime(22.5 * 3600_000 + DAY_ROLLOVER_BUFFER_MS - 1);
    expect(onRollover).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onRollover).toHaveBeenCalledTimes(1);
  });

  it('clears its timer on unmount', () => {
    vi.setSystemTime(new Date('2026-11-03T10:59:00Z'));
    const onRollover = vi.fn();
    const { unmount } = renderHook(() => useDayRollover('Pacific/Auckland', onRollover));
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(2 * 24 * 3600_000);
    expect(onRollover).not.toHaveBeenCalled();
  });

  it('re-arms for the new zone when the stored timezone changes while mounted', () => {
    // 23:59 in Auckland; it is still only 03:59 the same day in Berlin (CET).
    vi.setSystemTime(new Date('2026-11-03T10:59:00Z'));
    const onRollover = vi.fn();
    const { rerender } = renderHook(({ tz }) => useDayRollover(tz, onRollover), {
      initialProps: { tz: 'Pacific/Auckland' },
    });
    rerender({ tz: 'Europe/Berlin' });
    // One timer only: the Auckland one was cleared, not left running beside it.
    expect(vi.getTimerCount()).toBe(1);

    // Auckland's midnight passes: nothing, the user is in Berlin now.
    vi.advanceTimersByTime(60_000 + DAY_ROLLOVER_BUFFER_MS);
    expect(onRollover).not.toHaveBeenCalled();

    // Berlin's midnight is 2026-11-03T23:00Z, 12 h 1 min after the start.
    vi.advanceTimersByTime(12 * 3600_000 - 1);
    expect(onRollover).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onRollover).toHaveBeenCalledTimes(1);
  });

  it('calls the latest callback passed in, not the one it was mounted with', () => {
    vi.setSystemTime(new Date('2026-11-03T10:59:00Z'));
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = renderHook(({ cb }) => useDayRollover('Pacific/Auckland', cb), {
      initialProps: { cb: first },
    });
    rerender({ cb: second });
    vi.advanceTimersByTime(60_000 + DAY_ROLLOVER_BUFFER_MS);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });
});
