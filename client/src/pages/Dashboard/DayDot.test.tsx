import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import DayDot from './DayDot';

// A dot takes the worst status across calories and macros, so it can be red
// under an amber ring. It has to say which metric decided that, and which day
// it is — the ISO date alone told nobody anything.

describe('DayDot', () => {
  it('explains a red dot with the date and the deciding macro', () => {
    render(
      <DayDot
        date="2026-10-27"
        status="over_threshold"
        reason={{ metric: 'fat', total: 92, goal: 70, mode: 'limit' }}
        isToday={false}
        isSelected={false}
        onClick={vi.fn()}
      />,
    );
    const dot = screen.getByRole('button');
    expect(dot).toHaveAttribute('title', 'Tue, Oct 27 — well over goal: Fat 31% over');
    expect(dot).toHaveAttribute('aria-label', '2026-10-27: well over goal, Fat 31% over, Tue, Oct 27');
  });

  it('names a missed target as under', () => {
    render(
      <DayDot
        date="2026-10-28"
        status="over"
        reason={{ metric: 'protein', total: 99, goal: 110, mode: 'target' }}
        isToday={false}
        isSelected={false}
        onClick={vi.fn()}
      />,
    );
    expect(screen.getByRole('button')).toHaveAttribute('title', 'Wed, Oct 28 — over goal: Protein 10% under target');
  });

  it('shows the day of month so wrapped rows read in order', () => {
    render(<DayDot date="2026-10-05" status="none" isToday isSelected={false} onClick={vi.fn()} />);
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByRole('button')).toHaveAttribute('title', 'Mon, Oct 5 — no entries');
  });
});
