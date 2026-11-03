import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { PlanResponse } from '@/types';
import Plan from './Plan';

vi.mock('@/hooks/useAuth', () => ({
  useRequireAuth: () => ({ user: { id: 1, weightUnit: 'kg' }, isLoading: false }),
}));
vi.mock('@/api/plan', () => ({
  getPlan: vi.fn(),
  applyBudget: vi.fn(),
  updateMetrics: vi.fn(),
  clearMetrics: vi.fn(),
  upsertGoal: vi.fn(),
  abandonGoal: vi.fn(),
}));

import { getPlan } from '@/api/plan';

// The server sends its disclaimer in English and the projected date as a bare
// ISO day. The page shows both in the UI language: the disclaimer from the
// catalog, the date in the shared long day style.

const PLAN: PlanResponse = {
  unit: 'kg',
  metrics: { heightCm: 180, birthYear: 1990, sex: 'male', activityLevel: 'moderate', complete: true },
  currentWeight: 87.5,
  bmi: 27,
  bmiCategory: 'overweight',
  composition: null,
  healthyRange: { min: 59.9, max: 80.7 },
  goal: { target_weight: 80, start_weight: 92.5, pace_mode: 'rate', rate_per_week: 0.5, target_date: null } as unknown as PlanResponse['goal'],
  computed: null,
  trend: { slopePerWeek: -0.5, hasData: true, projectedWeeks: 14, projectedDate: '2027-02-07', status: 'on_track' },
  currentCalorieGoal: 2000,
  series: [],
  warnings: [],
  disclaimer: 'This plan is an estimate (server copy).',
};

function renderPlan() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Plan />
    </QueryClientProvider>,
  );
}

describe('Plan page in German', () => {
  beforeEach(async () => {
    vi.mocked(getPlan).mockResolvedValue(PLAN);
    await i18n.changeLanguage('de');
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('shows the translated disclaimer, not the server copy', async () => {
    renderPlan();
    expect(await screen.findByText(/^Dieser Plan ist eine Schätzung/)).toBeInTheDocument();
    expect(screen.queryByText('This plan is an estimate (server copy).')).not.toBeInTheDocument();
  });

  it('labels and formats the at-current-trend date', async () => {
    renderPlan();
    expect(await screen.findByText('Beim aktuellen Trend: 7. Feb. 2027')).toBeInTheDocument();
    expect(screen.queryByText(/2027-02-07/)).not.toBeInTheDocument();
  });
});
