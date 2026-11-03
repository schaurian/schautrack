import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { computeMacroStatus } from '@/lib/macros';
import TodayPanel from './TodayPanel';

// The ring used to read "1720 / 2200" and stop there, and a macro bar past its
// target was simply full — 134/110 looked the same as 110/110.

function renderPanel(opts: { total: number; goal: number | null; protein: number; proteinMode?: string }) {
  const proteinMode = opts.proteinMode ?? 'limit';
  return render(
    <TodayPanel
      dailyGoal={opts.goal}
      todayTotal={opts.total}
      caloriesEnabled
      calorieStatus={computeMacroStatus(opts.total, opts.goal, 'limit', 10)}
      enabledMacros={['protein']}
      macroGoals={{ protein: 110 }}
      todayMacroTotals={{ protein: opts.protein }}
      macroStatuses={{ protein: computeMacroStatus(opts.protein, 110, proteinMode, 10) }}
      macroModes={{ calories: 'limit', protein: proteinMode }}
      selectedDate="2026-11-03"
      todayStr="2026-11-03"
    />,
  );
}

describe('TodayPanel remaining/over feedback', () => {
  it('shows calories left under the ring', () => {
    renderPanel({ total: 1720, goal: 2200, protein: 50 });
    expect(screen.getByTestId('calorie-delta')).toHaveTextContent('480 left');
  });

  it('shows calories over in the threshold colour', () => {
    renderPanel({ total: 2500, goal: 2200, protein: 50 });
    const delta = screen.getByTestId('calorie-delta');
    expect(delta).toHaveTextContent('+300 over');
    // 300 over 2200 is past the 10% threshold: red, like the ring.
    expect(delta).toHaveStyle({ color: '#ef4444' });
  });

  it('shows no delta without a calorie goal', () => {
    renderPanel({ total: 500, goal: null, protein: 50 });
    expect(screen.queryByTestId('calorie-delta')).toBeNull();
  });

  it('marks a macro past its limit with "+N over" and a goal tick', () => {
    renderPanel({ total: 1720, goal: 2200, protein: 134 });
    expect(screen.getByTestId('macro-delta-protein')).toHaveTextContent('+24 over');
    const marker = screen.getByTestId('macro-goal-marker-protein');
    // The goal sits at 110/134 of the bar, not at its end.
    expect(marker.style.left).toBe(`${(110 / 134) * 100}%`);
    expect(screen.getByRole('img', { name: /Protein: 134 \/ 110 g, \+24 over/ })).toBeInTheDocument();
  });

  it('shows grams left and no tick under the limit', () => {
    renderPanel({ total: 1720, goal: 2200, protein: 86 });
    expect(screen.getByTestId('macro-delta-protein')).toHaveTextContent('24 left');
    expect(screen.queryByTestId('macro-goal-marker-protein')).toBeNull();
  });

  it('says "to go" for a target not yet reached', () => {
    renderPanel({ total: 1720, goal: 2200, protein: 80, proteinMode: 'target' });
    expect(screen.getByTestId('macro-delta-protein')).toHaveTextContent('30 to go');
  });
});
