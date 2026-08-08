import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { QuantityStepper } from './QuantityStepper';

// QuantityStepper is a controlled component whose entire job is the clamp:
// it never holds state, it just reports what the next value should be. That
// makes the interesting cases the boundaries, and boundaries are exactly what
// an E2E test covers badly — driving a stepper to 99 through the browser is 98
// clicks and a slow test, whereas here it is one render at the boundary.

describe('QuantityStepper', () => {
  const dec = () => screen.getByRole('button', { name: 'Decrease quantity' });
  const inc = () => screen.getByRole('button', { name: 'Increase quantity' });

  it('reports the incremented and decremented value without holding state', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<QuantityStepper value={3} onChange={onChange} />);

    await user.click(inc());
    expect(onChange).toHaveBeenLastCalledWith(4);

    await user.click(dec());
    expect(onChange).toHaveBeenLastCalledWith(2);

    // Controlled: the displayed value follows the prop, not the clicks. If it
    // ever held internal state, the two clicks above would have moved it.
    expect(screen.getByText('3×')).toBeInTheDocument();
  });

  it('disables the controls at each bound rather than emitting out-of-range values', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    const { unmount } = render(<QuantityStepper value={1} onChange={onChange} min={1} max={5} />);
    expect(dec()).toBeDisabled();
    await user.click(dec());
    expect(onChange).not.toHaveBeenCalled();
    unmount();

    render(<QuantityStepper value={5} onChange={onChange} min={1} max={5} />);
    expect(inc()).toBeDisabled();
    await user.click(inc());
    expect(onChange).not.toHaveBeenCalled();
  });

  it('clamps a value that arrives outside the range back into it', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    // A saved food restored with a stale quantity, or a hand-edited payload,
    // can hand the component a value outside [min,max]. Incrementing from
    // there must land inside the range, not one step further outside it.
    render(<QuantityStepper value={200} onChange={onChange} min={1} max={99} />);
    await user.click(dec());
    expect(onChange).toHaveBeenLastCalledWith(99);
  });

  it('truncates a fractional value instead of propagating it', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    // The clamp runs Math.trunc: quantities are counts, and "2.5×" of a saved
    // food is not a thing the API accepts.
    render(<QuantityStepper value={2.7} onChange={onChange} min={1} max={99} />);
    await user.click(inc());
    expect(onChange).toHaveBeenLastCalledWith(3);
    expect(Number.isInteger(onChange.mock.lastCall?.[0])).toBe(true);
  });

  it('exposes a labelled group and named controls for assistive tech', () => {
    render(<QuantityStepper value={1} onChange={vi.fn()} label="Servings" />);

    expect(screen.getByRole('group', { name: 'Servings' })).toBeInTheDocument();
    // The buttons render as "−" and "+", which a screen reader announces as
    // little on its own; the aria-labels are what make them usable.
    expect(dec()).toBeInTheDocument();
    expect(inc()).toBeInTheDocument();
  });
});
