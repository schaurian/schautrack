import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SavedFood } from '@/types';
import Toaster from '@/components/ui/Toaster';
import { useToastStore } from '@/stores/toastStore';
import SavedFoodsModal from './SavedFoodsModal';

// Deleting saved foods in a row must leave one delete toast — the latest —
// like entry deletes do. Deletes are immediate; Undo re-creates the food.

vi.mock('@/api/savedFoods', () => ({
  listSavedFoods: vi.fn(),
  deleteSavedFood: vi.fn(),
  createSavedFood: vi.fn(),
  updateSavedFood: vi.fn(),
}));

import { createSavedFood, deleteSavedFood, listSavedFoods } from '@/api/savedFoods';

const food = (id: number): SavedFood => ({
  id,
  name: `Food ${id}`,
  emoji: null,
  amount: 100 * id,
  macros: { protein: null, carbs: null, fat: null, fiber: null, sugar: null },
  use_count: 0,
  last_used_at: null,
  owner: null,
});

describe('SavedFoodsModal delete toast', () => {
  beforeEach(() => {
    for (const t of useToastStore.getState().toasts) useToastStore.getState().removeToast(t.id);
    vi.mocked(listSavedFoods).mockResolvedValue({ ok: true, savedFoods: [food(1), food(2), food(3)] } as never);
    vi.mocked(deleteSavedFood).mockReset().mockResolvedValue({ ok: true } as never);
    vi.mocked(createSavedFood).mockReset().mockResolvedValue({ ok: true } as never);
  });

  it('shows one toast for rapid deletes and undoes only the latest', async () => {
    // The open Radix dialog sets pointer-events: none on <body>. This test is
    // about which toast is shown and what its Undo restores, so skip that check.
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <SavedFoodsModal isOpen onClose={() => {}} />
        <Toaster />
      </QueryClientProvider>,
    );

    const buttons = await screen.findAllByRole('button', { name: 'Delete saved food' });
    await user.click(buttons[0]);
    await waitFor(() => expect(screen.getByText('Deleted Food 1')).toBeInTheDocument());
    await user.click(buttons[1]);
    await waitFor(() => expect(deleteSavedFood).toHaveBeenCalledTimes(2));

    await waitFor(() => expect(screen.getByText('Deleted Food 2')).toBeInTheDocument());
    expect(screen.queryByText('Deleted Food 1')).toBeNull();
    // The modal aria-hides everything outside it, so find the Undo by its hook.
    const undo = document.querySelectorAll<HTMLButtonElement>('[data-toast-control="action"]');
    expect(undo).toHaveLength(1);

    await user.click(undo[0]);
    await waitFor(() => expect(createSavedFood).toHaveBeenCalledTimes(1));
    expect(vi.mocked(createSavedFood).mock.calls[0][0]).toMatchObject({ name: 'Food 2', amount: 200 });
  });

  // use_count/last_used_at rank the chips; an Undo without them dropped the
  // restored food to the end of the row and lost its "N×" count.
  it('undo restores the food with its use count and last-used time', async () => {
    const used = { ...food(1), use_count: 7, last_used_at: '2026-10-30T08:15:00Z' };
    vi.mocked(listSavedFoods).mockResolvedValue({ ok: true, savedFoods: [used] } as never);
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <SavedFoodsModal isOpen onClose={() => {}} />
        <Toaster />
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole('button', { name: 'Delete saved food' }));
    await waitFor(() => expect(screen.getByText('Deleted Food 1')).toBeInTheDocument());
    await user.click(document.querySelector<HTMLButtonElement>('[data-toast-control="action"]')!);

    await waitFor(() => expect(createSavedFood).toHaveBeenCalledTimes(1));
    expect(vi.mocked(createSavedFood).mock.calls[0][0]).toMatchObject({
      name: 'Food 1', use_count: 7, last_used_at: '2026-10-30T08:15:00Z',
    });
  });
});
