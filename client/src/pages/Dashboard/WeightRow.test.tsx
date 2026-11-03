import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { WeightEntry } from '@/types';
import WeightRow from './WeightRow';

vi.mock('@/api/weight', () => ({ upsertWeight: vi.fn(), deleteWeight: vi.fn() }));

// A linked user's read-only row, carried over from an earlier day: the weight
// and body fat print with the locale's decimal separator and the reading's day
// in the shared long style, not as "87.5" / "2026-10-22" in every language.

const last: WeightEntry = { id: 1, entry_date: '2026-10-22', weight: 87.46, body_fat: 21.04 };

// Carried over: no reading on the selected day, the last one shows with its date.
// Same day: the reading belongs to the selected day, so body fat shows too.
function renderRow(sameDay = false) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <WeightRow
        weightEntry={sameDay ? last : null}
        lastWeightEntry={last}
        weightUnit="kg"
        canEdit={false}
        selectedDate={sameDay ? last.entry_date : '2026-10-24'}
      />
    </QueryClientProvider>,
  );
}

describe('WeightRow read-only formatting', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('uses English separators and the long day style', () => {
    renderRow();
    expect(screen.getByText('87.5')).toBeInTheDocument();
    expect(screen.getByText(/^Oct 22, 2026 · /)).toBeInTheDocument();
  });

  describe('in German', () => {
    beforeEach(async () => {
      await i18n.changeLanguage('de');
    });

    it('uses a decimal comma and the German day', () => {
      renderRow();
      expect(screen.getByText('87,5')).toBeInTheDocument();
      expect(screen.getByText(/^22\. Okt\. 2026 · /)).toBeInTheDocument();
      expect(screen.queryByText(/2026-10-22/)).not.toBeInTheDocument();
    });

    it('prints body fat with a decimal comma', () => {
      renderRow(true);
      expect(screen.getByText('21,0')).toBeInTheDocument();
    });
  });
});
