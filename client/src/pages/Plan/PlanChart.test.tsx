import { render } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
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
    expect(labels).toContain('Sep 1, 26');
    expect(labels).toContain('Jan 1, 27');
    expect(labels).not.toContain('Aug 31, 26');
    expect(labels).not.toContain('Dec 31, 26');
  });
});
