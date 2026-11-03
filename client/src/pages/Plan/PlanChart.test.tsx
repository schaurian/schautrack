import { render } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import PlanChart from './PlanChart';

// The series dates are calendar days ("YYYY-MM-DD"). Parsed with new Date()
// they become UTC midnight, and the x-axis labels — formatted in the browser's
// zone — showed every endpoint one day early west of UTC: a first weigh-in on
// Sep 1 was labelled "Aug 31".
const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
const originalTz = env.TZ;
afterEach(() => {
  env.TZ = originalTz;
});

describe.each(['America/Los_Angeles', 'Pacific/Auckland', 'UTC'])('PlanChart x-axis in %s', (zone) => {
  it('labels the first and last weigh-in with their own calendar days', () => {
    env.TZ = zone;
    const { container } = render(
      <PlanChart
        weightUnit="kg"
        series={[
          { date: '2026-09-01', weight: 82 },
          { date: '2026-10-25', weight: 80 },
          { date: '2027-01-01', weight: 79 },
        ]}
      />,
    );
    const labels = [...container.querySelectorAll('text')].map((n) => n.textContent);
    expect(labels).toContain('Sep 1, 2026');
    expect(labels).toContain('Jan 1, 2027');
    expect(labels).not.toContain('Aug 31, 2026');
    expect(labels).not.toContain('Dec 31, 2026');
  });
});

describe('PlanChart "today" uses the stored zone', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('anchors the plan curve on the user\'s day, not the browser\'s', () => {
    // Browser in LA (Nov 3, 11:00); the user's stored zone is Auckland, where
    // it is already Nov 4 — the day the server dated the ETA from.
    env.TZ = 'America/Los_Angeles';
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-03T19:00:00Z'));
    const { container } = render(
      <PlanChart
        weightUnit="kg"
        timeZone="Pacific/Auckland"
        series={[
          { date: '2026-09-01', weight: 82 },
          { date: '2026-11-04', weight: 80 },
        ]}
        planCurve={[
          { week: 0, weight: 80 },
          { week: 2, weight: 79 },
        ]}
      />,
    );
    const labels = [...container.querySelectorAll('text')].map((n) => n.textContent);
    // The curve ends two weeks after the user's today (Nov 4 + 14 = Nov 18).
    expect(labels).toContain('Nov 18, 26');
    expect(labels).not.toContain('Nov 17, 26');
  });
});
