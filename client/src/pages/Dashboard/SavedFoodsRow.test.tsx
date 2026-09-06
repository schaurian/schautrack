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
  listSavedFoodsWithShared: vi.fn(),
  trackSavedFood: vi.fn(),
  createSavedFood: vi.fn(),
  updateSavedFood: vi.fn(),
  deleteSavedFood: vi.fn(),
}));

vi.mock('@/api/entries', () => ({
  deleteEntry: vi.fn(),
}));

import { listSavedFoodsWithShared, trackSavedFood } from '@/api/savedFoods';

const food = (id: number, owner: string | null = null): SavedFood => ({
  id,
  name: `Food ${id}`,
  emoji: null,
  amount: 100 * id,
  macros: { protein: null, carbs: null, fat: null, fiber: null, sugar: null },
  use_count: 0,
  last_used_at: null,
  owner,
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
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({ ok: true, savedFoods: TEN_FOODS });
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
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({ ok: true, savedFoods: [food(1), food(2)] });
    renderRow();

    await screen.findAllByRole('button', { name: 'Food 1' });
    expect(screen.queryByRole('button', { name: '+ more' })).toBeNull();
  });

  // --- Shared quick-adds (#537) -------------------------------------------

  it('shows a food a friend shares in its own group, not behind "+ more"', async () => {
    // Eight of the caller's own foods is already past the mobile cut, so a
    // borrowed food ranked into the same list would be invisible until the
    // overflow is opened — the whole feature hidden behind a tap.
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({
      ok: true,
      savedFoods: [...Array.from({ length: 8 }, (_, i) => food(i + 1)), food(99, 'Alex')],
    });
    renderRow();

    expect(await screen.findByRole('button', { name: /Food 99/ })).toBeInTheDocument();
    expect(screen.getByTestId('saved-foods-shared')).toBeInTheDocument();
  });

  it('says whose food a borrowed chip is', async () => {
    // Nothing is copied, so tapping this logs whatever the owner currently has
    // it set to. The attribution is what makes that honest rather than a
    // surprise, so it is asserted on the accessible name, not just a tooltip.
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({
      ok: true,
      savedFoods: [food(1), food(2, 'Alex')],
    });
    renderRow();

    expect(await screen.findByRole('button', { name: 'Food 2, shared by Alex' })).toBeInTheDocument();
  });

  it('logs a borrowed food to the caller', async () => {
    const user = userEvent.setup();
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({
      ok: true,
      savedFoods: [food(1), food(42, 'Alex')],
    });
    renderRow();

    await user.click(await screen.findByRole('button', { name: /Food 42/ }));
    await waitFor(() => {
      expect(trackSavedFood).toHaveBeenCalledWith(42, '2026-08-30', 1);
    });
  });

  it('does not count borrowed foods toward the overflow control', async () => {
    // "+ more" folds the caller's OWN list. Borrowed foods live in their own
    // group, so two own foods plus a pile of borrowed ones must not sprout an
    // overflow control that would fold nothing.
    vi.mocked(listSavedFoodsWithShared).mockResolvedValue({
      ok: true,
      savedFoods: [food(1), food(2), ...Array.from({ length: 8 }, (_, i) => food(i + 20, 'Alex'))],
    });
    renderRow();

    await screen.findAllByRole('button', { name: 'Food 1' });
    expect(screen.queryByRole('button', { name: '+ more' })).toBeNull();
  });
});
