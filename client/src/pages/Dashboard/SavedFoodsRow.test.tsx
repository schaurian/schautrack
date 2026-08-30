import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SavedFood } from '@/types';
import SavedFoodsRow from './SavedFoodsRow';

// The quick-add row shows the first 8 foods on desktop / 6 on mobile and folds
// the rest behind "+ more". Everything past that cut is only reachable through
// that control, so what it opens has to be able to track — issue #489, where
// "+ more" opened the Manage list instead and clicking a food there started a
// rename rather than logging an entry.

vi.mock('@/api/savedFoods', () => ({
  listSavedFoods: vi.fn(),
  trackSavedFood: vi.fn(),
  createSavedFood: vi.fn(),
  updateSavedFood: vi.fn(),
  deleteSavedFood: vi.fn(),
}));

vi.mock('@/api/entries', () => ({
  deleteEntry: vi.fn(),
}));

import { listSavedFoods, trackSavedFood } from '@/api/savedFoods';

const food = (id: number): SavedFood => ({
  id,
  name: `Food ${id}`,
  emoji: null,
  amount: 100 * id,
  macros: { protein: null, carbs: null, fat: null, fiber: null, sugar: null },
  use_count: 0,
  last_used_at: null,
});

/** More than DESKTOP_CHIPS (8), so 9 and 10 sit in the overflow at every width. */
const TEN_FOODS = Array.from({ length: 10 }, (_, i) => food(i + 1));

function renderRow() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SavedFoodsRow selectedDate="2026-08-30" />
    </QueryClientProvider>,
  );
}

const chip = (name: string) => screen.getByRole('button', { name });

describe('SavedFoodsRow overflow', () => {
  beforeEach(() => {
    vi.mocked(listSavedFoods).mockResolvedValue({ ok: true, savedFoods: TEN_FOODS });
    vi.mocked(trackSavedFood).mockResolvedValue({
      ok: true,
      entry: { id: 4242 } as never,
    });
  });

  it('tracks a food that is only reachable through "+ more"', async () => {
    const user = userEvent.setup();
    renderRow();

    // Food 10 is past the cut at both widths, so it is not on screen yet.
    // Food 1 matches twice: the row renders a desktop and a mobile list and
    // hides one of them with CSS, which jsdom does not apply.
    await screen.findAllByRole('button', { name: 'Food 1' });
    expect(screen.queryByRole('button', { name: 'Food 10' })).toBeNull();

    await user.click(chip('+ more'));

    // Whatever "+ more" reveals, clicking a food in it must log that food —
    // it is the only path to these entries.
    await user.click(await screen.findByRole('button', { name: 'Food 10' }));

    await waitFor(() => {
      expect(trackSavedFood).toHaveBeenCalledWith(10, '2026-08-30', 1);
    });
  });

  it('folds the overflow away again', async () => {
    const user = userEvent.setup();
    renderRow();

    await user.click(await screen.findByRole('button', { name: '+ more' }));
    expect(screen.getByRole('button', { name: 'Food 10' })).toBeInTheDocument();

    await user.click(chip('− less'));
    expect(screen.queryByRole('button', { name: 'Food 10' })).toBeNull();
    expect(chip('+ more')).toBeInTheDocument();
  });

  it('offers no overflow control when every food already fits', async () => {
    vi.mocked(listSavedFoods).mockResolvedValue({ ok: true, savedFoods: [food(1), food(2)] });
    renderRow();

    await screen.findAllByRole('button', { name: 'Food 1' });
    expect(screen.queryByRole('button', { name: '+ more' })).toBeNull();
  });
});
