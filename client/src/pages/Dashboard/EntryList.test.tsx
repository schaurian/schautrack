import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Entry } from '@/types';
import Toaster from '@/components/ui/Toaster';
import { useToastStore } from '@/stores/toastStore';
import EntryList from './EntryList';

// Deleting entries in a row must leave one "Entry deleted" toast on screen —
// the one for the latest delete — not a stack of them. The server deletes
// immediately (there is no soft delete; Undo re-creates from a snapshot), so
// the earlier deletes are already committed and only lose their Undo.

vi.mock('@/api/entries', () => ({
  deleteEntry: vi.fn(),
  createEntry: vi.fn(),
  updateEntry: vi.fn(),
}));

vi.mock('@/api/savedFoods', () => ({
  saveEntryAsFood: vi.fn(),
}));

import { createEntry, deleteEntry } from '@/api/entries';

const entry = (id: number, name: string, amount: number): Entry => ({
  id,
  date: '2026-11-03',
  time: '12:00',
  amount,
  name,
  macros: null,
});

const ENTRIES = [entry(1, 'Apple', 95), entry(2, 'Bread', 250), entry(3, 'Cheese', 400)];

function renderList() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <EntryList entries={ENTRIES} canEdit enabledMacros={[]} caloriesEnabled autoCalcCalories={false} />
      <Toaster />
    </QueryClientProvider>,
  );
}

describe('EntryList delete toast', () => {
  beforeEach(() => {
    for (const t of useToastStore.getState().toasts) useToastStore.getState().removeToast(t.id);
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
    vi.mocked(createEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });

  it('shows a single toast for rapid deletes and undoes only the latest', async () => {
    const user = userEvent.setup();
    renderList();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete entry' });

    await user.click(deleteButtons[0]);
    await user.click(deleteButtons[1]);

    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    // Both deletes reached the server: the first is committed, not left pending.
    expect(deleteEntry).toHaveBeenNthCalledWith(1, 1);
    expect(deleteEntry).toHaveBeenNthCalledWith(2, 2);

    expect(screen.getAllByText('Entry deleted')).toHaveLength(1);
    const undo = screen.getAllByRole('button', { name: 'Undo' });
    expect(undo).toHaveLength(1);

    await user.click(undo[0]);

    await waitFor(() => expect(createEntry).toHaveBeenCalledTimes(1));
    // Undo restores the second entry (Bread), never the first.
    expect(createEntry).toHaveBeenCalledWith({ entry_date: '2026-11-03', entry_name: 'Bread', amount: 250 });
    expect(screen.queryByText('Entry deleted')).toBeNull();
  });

  it('plays the replace animation on the toast that took over the slot', async () => {
    const user = userEvent.setup();
    renderList();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete entry' });

    await user.click(deleteButtons[0]);
    const firstToast = (await screen.findByText('Entry deleted')).parentElement;
    expect(firstToast).not.toHaveClass('animate-toast-replace');

    await user.click(deleteButtons[2]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    const toast = screen.getByText('Entry deleted').parentElement;
    expect(toast).toHaveClass('animate-toast-replace');
  });

  it('remounts the toast on every replacement', async () => {
    // A new DOM node is what replays the animation and makes the live region
    // announce the delete again; an in-place update would do neither.
    const user = userEvent.setup();
    renderList();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete entry' });
    const toastEl = () => screen.getByText('Entry deleted').parentElement;

    await user.click(deleteButtons[0]);
    await screen.findByText('Entry deleted');
    let prev = toastEl();
    for (const [i, button] of [deleteButtons[1], deleteButtons[2]].entries()) {
      await user.click(button);
      await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(i + 2));
      const now = toastEl();
      expect(now).not.toBe(prev);
      expect(prev?.isConnected).toBe(false);
      prev = now;
    }
    expect(screen.getAllByText('Entry deleted')).toHaveLength(1);
  });

  it('follows the delete clicked last, not the response that arrived last', async () => {
    const user = userEvent.setup();
    let finishFirst: (v: unknown) => void = () => {};
    vi.mocked(deleteEntry)
      .mockImplementationOnce(() => new Promise((resolve) => { finishFirst = resolve; }) as never)
      .mockResolvedValueOnce({ ok: true } as never);
    renderList();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete entry' });

    await user.click(deleteButtons[0]); // Apple: response held back
    await user.click(deleteButtons[1]); // Bread: answers at once
    await screen.findByText('Entry deleted');

    finishFirst({ ok: true });
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    // Let Apple's late continuation run.
    await new Promise((r) => setTimeout(r, 0));

    expect(screen.getAllByText('Entry deleted')).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: 'Undo' }));
    await waitFor(() => expect(createEntry).toHaveBeenCalledTimes(1));
    expect(createEntry).toHaveBeenCalledWith({ entry_date: '2026-11-03', entry_name: 'Bread', amount: 250 });
  });
});
