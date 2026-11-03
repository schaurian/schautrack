import { act, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { useToastStore } from '@/stores/toastStore';
import Toaster from './Toaster';

// A replaced toast remounts (see Toaster). If keyboard focus was inside it,
// the old node takes focus with it to <body>; the new toast must take it back
// on the same control.

const add = (onClick = () => {}) =>
  act(() => {
    useToastStore.getState().addToast('success', 'Entry deleted', { label: 'Undo', onClick }, { replaceKey: 'entry-delete' });
  });

describe('Toaster replacement focus', () => {
  beforeEach(() => {
    for (const t of useToastStore.getState().toasts) useToastStore.getState().removeToast(t.id);
  });

  it('keeps focus on the same control when the toast is replaced', () => {
    render(<Toaster />);
    add();
    const oldUndo = screen.getByRole('button', { name: 'Undo' });
    act(() => oldUndo.focus());

    add();
    const newUndo = screen.getByRole('button', { name: 'Undo' });
    expect(newUndo).not.toBe(oldUndo);
    expect(document.activeElement).toBe(newUndo);
  });

  it('restores focus to the dismiss control too', () => {
    render(<Toaster />);
    add();
    act(() => screen.getByRole('button', { name: 'Dismiss' }).focus());
    add();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Dismiss' }));
  });

  it('does not pull focus into a replaced toast that did not have it', () => {
    render(
      <>
        <button type="button">Elsewhere</button>
        <Toaster />
      </>,
    );
    add();
    const elsewhere = screen.getByRole('button', { name: 'Elsewhere' });
    act(() => elsewhere.focus());
    add();
    expect(document.activeElement).toBe(elsewhere);
  });
});
