import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useToastStore } from './toastStore';

// A toast carrying a replace key occupies one slot: a second toast with the
// same key takes that slot over instead of stacking under it. Deleting three
// entries in a row used to pile up three "Entry deleted" toasts, each with its
// own Undo; only the latest one is wanted on screen.

const store = () => useToastStore.getState();

describe('toastStore replaceKey', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    for (const t of store().toasts) store().removeToast(t.id);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('replaces the toast holding the same key instead of stacking', () => {
    const first = vi.fn();
    const second = vi.fn();
    store().addToast('success', 'Entry deleted', { label: 'Undo', onClick: first }, { replaceKey: 'entry-delete' });
    store().addToast('success', 'Entry deleted', { label: 'Undo', onClick: second }, { replaceKey: 'entry-delete' });

    const { toasts } = store();
    expect(toasts).toHaveLength(1);
    // The visible Undo is the latest one: it must undo the second write only.
    toasts[0].action?.onClick();
    expect(second).toHaveBeenCalledTimes(1);
    expect(first).not.toHaveBeenCalled();
    // The revision marks the replacement so the Toaster can animate it.
    expect(toasts[0].revision).toBe(1);
  });

  it('restarts the auto-dismiss timer on replacement', () => {
    const action = { label: 'Undo', onClick: () => {} };
    store().addToast('success', 'Entry deleted', action, { replaceKey: 'entry-delete' });
    vi.advanceTimersByTime(8000);
    store().addToast('success', 'Entry deleted', action, { replaceKey: 'entry-delete' });
    // The first toast's 10s timer would have fired at 10s; the replacement
    // runs on a fresh one.
    vi.advanceTimersByTime(8000);
    expect(store().toasts).toHaveLength(1);
    vi.advanceTimersByTime(2001);
    expect(store().toasts).toHaveLength(0);
  });

  it('keeps stacking action toasts that carry no replace key', () => {
    const action = { label: 'Undo', onClick: () => {} };
    store().addToast('success', 'Deleted A', action);
    store().addToast('success', 'Deleted B', action);
    expect(store().toasts).toHaveLength(2);
  });

  it('does not replace a toast under a different key', () => {
    const action = { label: 'Undo', onClick: () => {} };
    store().addToast('success', 'Entry deleted', action, { replaceKey: 'entry-delete' });
    store().addToast('success', 'Deleted Apple', action, { replaceKey: 'saved-food-delete' });
    expect(store().toasts).toHaveLength(2);
  });
});
