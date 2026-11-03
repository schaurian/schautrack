import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Entry } from '@/types';
import Toaster from '@/components/ui/Toaster';
import { useToastStore } from '@/stores/toastStore';
import EntryList, { DELETE_REPEAT_GUARD_MS } from './EntryList';

// Deleting entries in a row must leave one "Entry deleted" toast on screen —
// the one for the latest delete — not a stack of them. The server deletes
// immediately (there is no soft delete; Undo re-creates from a snapshot), so
// the earlier deletes are already committed and only lose their Undo.

// Two deliberate deletes in a row: EntryList drops a delete that lands within
// DELETE_REPEAT_GUARD_MS of the previous one (double-tap protection, see the
// guard tests below), so these toast tests step a mocked clock past that
// window between clicks. Their subject is the toast, not the guard.
let now = 1_000_000;
const pastGuard = () => {
  now += DELETE_REPEAT_GUARD_MS + 600;
};

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
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    for (const t of useToastStore.getState().toasts) useToastStore.getState().removeToast(t.id);
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
    vi.mocked(createEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });

  it('shows a single toast for rapid deletes and undoes only the latest', async () => {
    const user = userEvent.setup();
    renderList();
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete entry' });

    await user.click(deleteButtons[0]);
    pastGuard();
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

    pastGuard();
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
      pastGuard();
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
    pastGuard();
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

const plainEntry = (id: number): Entry => ({
  id,
  date: '2026-11-03',
  time: '12:00',
  amount: 100 * id,
  name: `Entry ${id}`,
  macros: null,
});

function renderGuardList(entries: Entry[] = [plainEntry(1), plainEntry(2)]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const ui = (list: Entry[]) => (
    <QueryClientProvider client={client}>
      <EntryList entries={list} canEdit enabledMacros={[]} caloriesEnabled autoCalcCalories={false} />
    </QueryClientProvider>
  );
  const view = render(ui(entries));
  return { ...view, setEntries: (list: Entry[]) => view.rerender(ui(list)) };
}

// Deleting an entry reflows the list and the next row's delete button slides
// up under the pointer, so the second tap of a double-tap used to delete a
// second entry. EntryList drops a delete that arrives within the guard window
// of the previous one, or of the row it deleted leaving the list.
describe('EntryList delete repeat guard', () => {
  beforeEach(() => {
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
    vi.spyOn(Date, 'now').mockImplementation(() => now);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('ignores a delete on another row that follows the previous one within the window', async () => {
    renderGuardList();
    const [first, second] = screen.getAllByRole('button', { name: 'Delete entry' });

    fireEvent.click(first);
    now += 300; // a typical double-tap interval
    fireEvent.click(second);

    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(1));
    expect(deleteEntry).toHaveBeenCalledWith(1);
    // Give a wrongly-accepted second delete the chance to land before asserting.
    await new Promise((r) => setTimeout(r, 0));
    expect(deleteEntry).toHaveBeenCalledTimes(1);
  });

  // The row only moves once the delete and the refetch have round-tripped, so
  // the window has to be counted from the reflow too, not only from the tap.
  it('ignores a delete that lands just after the list lost a row, even when the first tap was long ago', async () => {
    const { setEntries } = renderGuardList([plainEntry(1), plainEntry(2), plainEntry(3)]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[0]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(1));

    now += 1000; // slow round trip: the list reflows well after the first tap
    setEntries([plainEntry(2), plainEntry(3)]);
    now += 300;
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[0]);
    await new Promise((r) => setTimeout(r, 0));
    expect(deleteEntry).toHaveBeenCalledTimes(1);

    now += 200; // 500ms after the reflow: a deliberate tap
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[0]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    expect(deleteEntry).toHaveBeenNthCalledWith(2, 2);
  });

  it('accepts the next delete once the window has passed', async () => {
    renderGuardList();
    const [first, second] = screen.getAllByRole('button', { name: 'Delete entry' });

    fireEvent.click(first);
    now += 500; // absolute, not DELETE_REPEAT_GUARD_MS-relative: pins the window
    fireEvent.click(second);

    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    expect(deleteEntry).toHaveBeenNthCalledWith(2, 2);
  });

  // Only the user's own delete arms the reflow window. A row vanishing because
  // another device deleted it (SSE refetch) or the day changed must not
  // swallow the next real tap.
  it('does not block a tap right after the list shrank for a reason other than this delete', async () => {
    const { setEntries } = renderGuardList([plainEntry(1), plainEntry(2), plainEntry(3)]);
    setEntries([plainEntry(2), plainEntry(3)]); // entry 1 removed elsewhere, refetched
    now += 10;
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[0]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(1));
    expect(deleteEntry).toHaveBeenCalledWith(2);
  });

  it('does not block a tap after another row vanished while an own delete is still pending', async () => {
    const { setEntries } = renderGuardList([plainEntry(1), plainEntry(2), plainEntry(3)]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[0]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(1));
    now += 1000;
    setEntries([plainEntry(1), plainEntry(2)]); // entry 3 removed elsewhere; entry 1 still shown
    now += 10;
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete entry' })[1]);
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    expect(deleteEntry).toHaveBeenNthCalledWith(2, 2);
  });
});
