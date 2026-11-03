import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import i18n from '@/i18n';
import type { SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import Timeline from './Timeline';

// The server labels the self view with the literal English "You" (API
// contract, unchanged). The timeline must name it from the catalog, or German
// shows "You" here while the entries header says "Du".

const view = (over: Partial<SharedView>): SharedView => ({
  userId: 1,
  email: 'me@example.com',
  label: 'You',
  isSelf: true,
  dailyGoal: 2000,
  goalThreshold: 10,
  dailyStats: [],
  todayStr: '2026-11-03',
  shares: { nutrition: true, weight: true, todos: true, notes: true, savedfoods: true },
  ...over,
});

const VIEWS = [view({}), view({ userId: 2, email: 'anna@example.com', label: 'Anna', isSelf: false, linkId: 9 })];

function renderTimeline() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <Timeline sharedViews={VIEWS} range={{ start: '2026-10-28', end: '2026-11-03', days: 7, preset: 7 }} todayStr="2026-11-03" />
    </QueryClientProvider>,
  );
}

describe('Timeline self label', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('de');
    useDashboardStore.setState({ currentUserId: 2, currentLabel: 'Anna', canEdit: false });
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('names the self view in the active language, not the server literal', () => {
    renderTimeline();
    expect(screen.getByText('Du')).toBeInTheDocument();
    expect(screen.queryByText('You')).not.toBeInTheDocument();
    // A friend keeps the label the server sends.
    expect(screen.getByText('Anna')).toBeInTheDocument();
  });

  it('stores the translated label when the self card is selected', async () => {
    renderTimeline();
    await userEvent.click(screen.getAllByTestId('share-card')[0]);
    expect(useDashboardStore.getState().currentLabel).toBe('Du');
    expect(useDashboardStore.getState().currentUserId).toBe(1);
  });
});
