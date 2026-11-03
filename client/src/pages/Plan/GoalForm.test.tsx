import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { PlanComputed, PlanWarning, WeightGoal } from '@/types';
import GoalForm from './GoalForm';

vi.mock('@/api/plan', () => ({ upsertGoal: vi.fn() }));

// The plan's ETA sat next to the progress card's "Projected" date as two bare
// ISO strings with no hint which was which. The ETA is the plan's own date and
// renders in the shared long day style of the active language.

const goal = { target_weight: 75, pace_mode: 'rate', rate_per_week: 0.5, target_date: null } as unknown as WeightGoal;
const computed = { etaDate: '2027-01-12', etaWeeks: 10, budgetKcal: 1800 } as unknown as PlanComputed;

function renderForm(warnings: PlanWarning[] = []) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <GoalForm goal={goal} computed={computed} warnings={warnings} weightUnit="kg" metricsComplete />
    </QueryClientProvider>,
  );
}

describe('GoalForm ETA', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('labels the plan date and formats it', () => {
    renderForm();
    expect(screen.getByText('Plan target date:')).toBeInTheDocument();
    expect(screen.getByText('Jan 12, 2027')).toBeInTheDocument();
    expect(screen.queryByText('2027-01-12')).not.toBeInTheDocument();
  });

  it('formats the date in German', async () => {
    await i18n.changeLanguage('de');
    renderForm();
    expect(screen.getByText('Zieldatum laut Plan:')).toBeInTheDocument();
    expect(screen.getByText('12. Jan. 2027')).toBeInTheDocument();
  });
});

describe('GoalForm warnings', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  // The server's warning `message` is English; its `code` is stable.
  it('translates a known warning by its code', async () => {
    await i18n.changeLanguage('de');
    renderForm([{ code: 'target_underweight', message: 'Your target weight falls in the underweight BMI range.' }]);
    expect(screen.getByText('Dein Zielgewicht liegt im BMI-Bereich Untergewicht.')).toBeInTheDocument();
  });

  it('falls back to the server message for an unknown code', async () => {
    await i18n.changeLanguage('de');
    renderForm([{ code: 'brand_new_code', message: 'Something new from the server.' }]);
    expect(screen.getByText('Something new from the server.')).toBeInTheDocument();
  });
});
