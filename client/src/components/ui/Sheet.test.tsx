import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Sheet } from './Sheet';

// The add-food dialog: focus goes to its first field, stays inside while it is
// open, and comes back to whatever opened it.

function Harness({ tick = 0 }: { tick?: number }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>Open</button>
      <button type="button">Outside</button>
      {/* A fresh inline onClose on every render, exactly like Dashboard passes. */}
      <Sheet open={open} onClose={() => setOpen(false)} title="Add food">
        <span data-tick={tick} />
        <button type="button">Quick add</button>
        <input aria-label="Food name" data-autofocus />
        <input aria-label="Calories" />
        <button type="button">Track</button>
      </Sheet>
    </>
  );
}

function setPointer(kind: 'fine' | 'coarse') {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(pointer: coarse)' && kind === 'coarse',
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

describe('Sheet focus management', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('focuses the marked first field on open, not the dialog container', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    expect(screen.getByRole('textbox', { name: 'Food name' })).toHaveFocus();
  });

  it('returns focus to the trigger when closed with Escape', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open' })).toHaveFocus();
  });

  it('traps Tab inside the dialog in both directions', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    screen.getByRole('button', { name: 'Track' }).focus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Quick add' })).toHaveFocus();
    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'Track' })).toHaveFocus();
  });

  it('keeps focus in the field being typed in when the parent re-renders', async () => {
    const user = userEvent.setup();
    const { rerender } = render(<Harness tick={0} />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    const calories = screen.getByRole('textbox', { name: 'Calories' });
    calories.focus();
    rerender(<Harness tick={1} />);
    expect(calories).toHaveFocus();
  });

  it('focuses the first field on a fine (mouse/keyboard) pointer', async () => {
    setPointer('fine');
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    expect(screen.getByRole('textbox', { name: 'Food name' })).toHaveFocus();
  });

  it('focuses the heading, not a field, on a coarse (touch) pointer', async () => {
    setPointer('coarse');
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    expect(screen.getByRole('heading', { name: 'Add food' })).toHaveFocus();
    expect(document.activeElement?.tagName).not.toBe('INPUT');

    // Trap and restore are unchanged: Shift+Tab from the heading wraps to the
    // last control instead of leaving the dialog, and Escape restores focus.
    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'Track' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Open' })).toHaveFocus();
  });

  it('leaves Escape inside a nested popover dialog to that popover', async () => {
    function Nested() {
      const [open, setOpen] = useState(true);
      const [popover, setPopover] = useState(true);
      return (
        <Sheet open={open} onClose={() => setOpen(false)} title="Add food">
          <input aria-label="Food name" data-autofocus />
          {popover && (
            <div role="dialog" aria-label="Quantity" onKeyDown={(e) => { if (e.key === 'Escape') setPopover(false); }}>
              <button type="button">Log 2</button>
            </div>
          )}
        </Sheet>
      );
    }
    const user = userEvent.setup();
    render(<Nested />);
    screen.getByRole('button', { name: 'Log 2' }).focus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Quantity' })).not.toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Add food' })).toBeInTheDocument();
    // A second Escape, now outside the popover, closes the sheet.
    screen.getByRole('textbox', { name: 'Food name' }).focus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Add food' })).not.toBeInTheDocument();
  });
});
