import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Entry } from '@/types';
import Toaster from '@/components/ui/Toaster';
import { useToastStore } from '@/stores/toastStore';
import EntryList, { DELETE_REPEAT_GUARD_MS } from './EntryList';

// Keyboard and screen-reader behaviour of the entries list: where focus goes
// after a delete or an inline edit, what the inline inputs are called, and that
// a save is confirmed at all (it used to happen in silence).

vi.mock('@/api/entries', () => ({
  updateEntry: vi.fn(),
  deleteEntry: vi.fn(),
  createEntry: vi.fn(),
}));

vi.mock('@/api/savedFoods', () => ({
  saveEntryAsFood: vi.fn(),
}));

import { deleteEntry, updateEntry } from '@/api/entries';
import { ApiError } from '@/api/client';

const entry = (id: number, name: string): Entry => ({
  id,
  date: '2026-11-03',
  time: '12:00',
  amount: 100 * id,
  name,
  macros: { protein: 10, carbs: null, fat: null, fiber: null, sugar: null },
});

function renderList(entries: Entry[], { withToaster = false } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      {withToaster && <Toaster />}
      <h2 id="entries-heading" tabIndex={-1}>Entries</h2>
      <EntryList
        entries={entries}
        canEdit
        enabledMacros={['protein']}
        caloriesEnabled
        autoCalcCalories={false}
        headingId="entries-heading"
      />
    </QueryClientProvider>,
  );
}

const deleteButtons = () => screen.getAllByRole('button', { name: 'Delete entry' });

describe('EntryList focus after delete', () => {
  beforeEach(() => {
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });

  it('moves focus to the next row’s delete button', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')]);
    await user.click(deleteButtons()[1]);
    await waitFor(() => expect(deleteButtons()[2]).toHaveFocus());
  });

  it('falls back to the previous row when the last row is deleted', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal')]);
    await user.click(deleteButtons()[1]);
    await waitFor(() => expect(deleteButtons()[0]).toHaveFocus());
  });

  it('also moves focus when the entry was already gone (404 counts as deleted)', async () => {
    vi.mocked(deleteEntry).mockRejectedValueOnce(new ApiError(404, 'Entry not found'));
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal')]);
    await user.click(deleteButtons()[0]);
    await waitFor(() => expect(deleteButtons()[1]).toHaveFocus());
  });

  it('falls back to the list heading when the only row is deleted', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple')]);
    await user.click(deleteButtons()[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Entries' })).toHaveFocus());
  });

  it('leaves focus alone if the user moved on before the delete finished', async () => {
    let resolve: (v: unknown) => void = () => {};
    vi.mocked(deleteEntry).mockReturnValue(new Promise((r) => { resolve = r; }) as never);
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal')]);
    await user.click(deleteButtons()[0]);
    const elsewhere = screen.getByRole('button', { name: 'Oatmeal' });
    elsewhere.focus();
    resolve({ ok: true });
    await waitFor(() => expect(deleteEntry).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(elsewhere).toHaveFocus();
  });
});

describe('EntryList focus after delete, with the delete toast mounted', () => {
  // EntryList drops a delete within DELETE_REPEAT_GUARD_MS of the previous one
  // (double-tap guard); deliberate deletes below wait that out on this clock.
  let now = 1000;
  afterEach(() => {
    vi.restoreAllMocks();
  });
  beforeEach(() => {
    now = 1000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    for (const t of useToastStore.getState().toasts) useToastStore.getState().removeToast(t.id);
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });

  // The delete toast is replaced on every delete, and the Toaster hands focus
  // over to the replacement only when focus was inside the old toast. Deleting
  // from the list must therefore keep focus in the list across the swap.
  it('keeps focus in the list while consecutive deletes replace the toast', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')], { withToaster: true });
    await user.click(deleteButtons()[0]);
    await waitFor(() => expect(deleteButtons()[1]).toHaveFocus());
    await screen.findByText('Entry deleted');
    now += DELETE_REPEAT_GUARD_MS + 100;
    await user.keyboard('{Enter}');
    await waitFor(() => expect(deleteButtons()[2]).toHaveFocus());
    expect(screen.getAllByText('Entry deleted')).toHaveLength(1);
  });

  it('leaves focus on the toast’s Undo when the user went there before the delete finished', async () => {
    let resolve: (v: unknown) => void = () => {};
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')], { withToaster: true });
    await user.click(deleteButtons()[0]);
    const undo = await screen.findByRole('button', { name: 'Undo' });
    vi.mocked(deleteEntry).mockReturnValue(new Promise((r) => { resolve = r; }) as never);
    now += DELETE_REPEAT_GUARD_MS + 100;
    await user.click(deleteButtons()[1]);
    undo.focus();
    resolve({ ok: true });
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Undo' })).toHaveFocus());
    expect(deleteButtons().some((b) => b === document.activeElement)).toBe(false);
  });
});

// The double-press window itself is EntryList's DELETE_REPEAT_GUARD_MS guard
// (mobile touch targets); these pin how it composes with focus moving to the
// next row, and the held-key case that window alone cannot stop.
describe('EntryList keyboard delete guard', () => {
  let now = 1000;
  beforeEach(() => {
    now = 1000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.mocked(deleteEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Focus lands on the next row's delete button after each delete, so without
  // a guard a held Enter (auto-repeat) walks down the list deleting every row.
  it('ignores auto-repeat while Enter is held', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')]);
    deleteButtons()[0].focus();
    // Each repeat arrives after the double-tap window (a real key repeat
    // starts after ~500ms), so only the e.repeat check can stop it.
    const tick = () => { now += DELETE_REPEAT_GUARD_MS + 200; };
    document.addEventListener('keydown', tick, true);
    await user.keyboard('{Enter>5/}');
    document.removeEventListener('keydown', tick, true);
    await waitFor(() => expect(deleteButtons()[1]).toHaveFocus());
    expect(deleteEntry).toHaveBeenCalledTimes(1);
    expect(deleteEntry).toHaveBeenCalledWith(1);
  });

  it('ignores a second keyboard delete within the double-press window', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')]);
    deleteButtons()[0].focus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(deleteButtons()[1]).toHaveFocus());
    now += DELETE_REPEAT_GUARD_MS / 2;
    await user.keyboard('{Enter}');
    expect(deleteEntry).toHaveBeenCalledTimes(1);
  });

  it('accepts a deliberate re-press after the window, keeping focus in the list', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple'), entry(2, 'Oatmeal'), entry(3, 'Pasta')]);
    deleteButtons()[0].focus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(deleteButtons()[1]).toHaveFocus());
    now += DELETE_REPEAT_GUARD_MS + 100;
    await user.keyboard('{Enter}');
    await waitFor(() => expect(deleteEntry).toHaveBeenCalledTimes(2));
    expect(deleteEntry).toHaveBeenLastCalledWith(2);
    await waitFor(() => expect(deleteButtons()[2]).toHaveFocus());
  });
});

describe('EntryList inline edit', () => {
  beforeEach(() => {
    vi.mocked(updateEntry).mockReset().mockResolvedValue({ ok: true } as never);
  });

  it('names each inline input after its field and entry', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple')]);

    await user.click(screen.getByRole('button', { name: 'Apple' }));
    expect(screen.getByRole('textbox', { name: 'Name for Apple' })).toHaveFocus();
    await user.keyboard('{Escape}');

    await user.click(screen.getByRole('button', { name: /kcal/i }));
    expect(screen.getByRole('textbox', { name: 'Calories for Apple' })).toHaveFocus();
    await user.keyboard('{Escape}');

    await user.click(screen.getByRole('button', { name: /protein/i }));
    expect(screen.getByRole('textbox', { name: 'Protein for Apple' })).toHaveFocus();
  });

  it('confirms a save visibly and through a polite live region', async () => {
    const user = userEvent.setup();
    const { container } = renderList([entry(1, 'Apple')]);
    const live = container.querySelector('[aria-live="polite"]');
    expect(live).toBeInTheDocument();
    expect(live).toBeEmptyDOMElement();

    await user.click(screen.getByRole('button', { name: /kcal/i }));
    await user.clear(screen.getByRole('textbox', { name: 'Calories for Apple' }));
    await user.keyboard('250{Enter}');

    await waitFor(() => expect(live).toHaveTextContent('Calories for Apple saved'));
    expect(screen.getByTestId('entry-saved')).toHaveTextContent('Saved');
    expect(updateEntry).toHaveBeenCalledWith(1, { amount: 250 });
  });

  it('shows no confirmation when the save fails', async () => {
    vi.mocked(updateEntry).mockRejectedValue(new Error('nope'));
    const user = userEvent.setup();
    const { container } = renderList([entry(1, 'Apple')]);
    await user.click(screen.getByRole('button', { name: /kcal/i }));
    await user.keyboard('{Enter}');
    await waitFor(() => expect(updateEntry).toHaveBeenCalled());
    expect(container.querySelector('[aria-live="polite"]')).toBeEmptyDOMElement();
    expect(screen.queryByTestId('entry-saved')).not.toBeInTheDocument();
  });

  it('does not pull focus back after an invalid Enter followed by a Tab-away save', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple')]);
    await user.click(screen.getByRole('button', { name: /kcal/i }));
    const input = screen.getByRole('textbox', { name: 'Calories for Apple' });
    await user.clear(input);
    await user.keyboard('abc{Enter}');
    expect(input).toBeInTheDocument();
    await user.clear(input);
    await user.keyboard('300');
    // Leaving with Tab: focus goes where the user moved it, not back.
    await user.tab();
    const protein = screen.getByRole('button', { name: /protein/i });
    expect(protein).toHaveFocus();
    await waitFor(() => expect(updateEntry).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole('textbox')).not.toBeInTheDocument());
    expect(protein).toHaveFocus();
  });

  it('returns focus to the pill when the edit ends from the keyboard', async () => {
    const user = userEvent.setup();
    renderList([entry(1, 'Apple')]);

    await user.click(screen.getByRole('button', { name: /kcal/i }));
    await user.keyboard('{Enter}');
    await waitFor(() => expect(screen.getByRole('button', { name: /kcal/i })).toHaveFocus());

    await user.click(screen.getByRole('button', { name: /protein/i }));
    await user.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: /protein/i })).toHaveFocus();
  });
});
