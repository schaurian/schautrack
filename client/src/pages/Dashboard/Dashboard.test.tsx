import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { DashboardData, SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import Dashboard from './Dashboard';

vi.mock('@/hooks/useAuth', () => ({
  useRequireAuth: () => ({ user: { id: 1, email: 'me@example.com', weightUnit: 'kg' }, isLoading: false }),
}));
vi.mock('@/api/entries', () => ({
  getDashboard: vi.fn(),
  getDayEntries: vi.fn(),
  createEntry: vi.fn(),
  deleteEntry: vi.fn(),
  updateEntry: vi.fn(),
}));
vi.mock('@/api/weight', () => ({
  getWeightDay: vi.fn(),
  upsertWeight: vi.fn(),
  deleteWeight: vi.fn(),
  toggleBodyFatEnabled: vi.fn(),
}));
vi.mock('@/api/plan', () => ({ getPlan: vi.fn(() => new Promise(() => {})) }));
vi.mock('@/api/todos', () => ({ getTodosDay: vi.fn(() => new Promise(() => {})), getTodos: vi.fn(() => new Promise(() => {})) }));
vi.mock('@/api/notes', () => ({ getNote: vi.fn(() => new Promise(() => {})) }));
vi.mock('@/api/savedFoods', () => ({
  listSavedFoods: vi.fn(() => new Promise(() => {})),
  listSavedFoodsWithShared: vi.fn(() => new Promise(() => {})),
}));

import { getDashboard, getDayEntries } from '@/api/entries';
import { getWeightDay } from '@/api/weight';

// The entries header names the viewed user. For the self view that name has
// to come from the catalog at render time: the store keeps whatever label was
// current when the card was selected, so switching language afterwards must
// not leave the header saying "You" while the timeline says "Du".

const self: SharedView = {
  userId: 1,
  email: 'me@example.com',
  label: 'You',
  isSelf: true,
  dailyGoal: 2000,
  goalThreshold: 10,
  dailyStats: [],
  todayStr: '2026-11-03',
  shares: { nutrition: true, weight: true, todos: true, notes: true, savedfoods: true },
};

const DASHBOARD = {
  user: { id: 1, email: 'me@example.com' },
  dailyGoal: 2000,
  todayTotal: 0,
  selectedDate: '2026-11-03',
  sharedViews: [self],
  weightUnit: 'kg',
  timeZone: 'Europe/Berlin',
  todayStr: '2026-11-03',
  range: { start: '2026-10-28', end: '2026-11-03', days: 7, preset: 7 },
  weightEntry: null,
  lastWeightEntry: null,
  hasAiEnabled: false,
  aiUsage: null,
  aiProviderName: null,
  barcodeEnabled: false,
  caloriesEnabled: true,
  autoCalcCalories: false,
  enabledMacros: [],
  macroGoals: {},
  todayMacroTotals: {},
  macroLabels: {},
  macroModes: {},
  macroStatuses: {},
  calorieStatus: { statusClass: '', statusText: '' },
} as unknown as DashboardData;

describe('Dashboard entries header', () => {
  beforeEach(async () => {
    vi.mocked(getDashboard).mockResolvedValue(DASHBOARD);
    vi.mocked(getDayEntries).mockResolvedValue({ entries: [] } as never);
    vi.mocked(getWeightDay).mockResolvedValue({ entry: null } as never);
    await i18n.changeLanguage('en');
    // Self already selected while the UI was English.
    useDashboardStore.setState({ selectedDate: '2026-11-03', currentUserId: 1, currentLabel: 'You', canEdit: true });
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('follows a language switch made after selecting the self view', async () => {
    render(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <Dashboard />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    expect(await screen.findByText('Tue, Nov 3 — You')).toBeInTheDocument();
    await act(async () => {
      await i18n.changeLanguage('de');
    });
    expect(await screen.findByText('Di., 3. Nov. — Du')).toBeInTheDocument();
  });
});
