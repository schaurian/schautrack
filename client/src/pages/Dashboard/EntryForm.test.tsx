import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import EntryForm from './EntryForm';

// Typing "abc" into a macro and pressing Track used to produce only a toast:
// the field was not marked and focus stayed on the button. And "2*150" was
// stored as 300 without the form ever showing that number.

vi.mock('@/api/entries', () => ({ createEntry: vi.fn() }));
vi.mock('@/api/savedFoods', () => ({ createSavedFood: vi.fn() }));

import { createEntry } from '@/api/entries';
import { ApiError } from '@/api/client';

function renderForm(overrides: Partial<React.ComponentProps<typeof EntryForm>> = {}) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <EntryForm
        selectedDate="2026-11-03"
        caloriesEnabled
        autoCalcCalories={false}
        enabledMacros={['protein', 'carbs', 'fat']}
        hasAiEnabled={false}
        aiUsage={null}
        aiProviderName={null}
        barcodeEnabled={false}
        onSubmit={() => {}}
        {...overrides}
      />
    </QueryClientProvider>,
  );
}

describe('EntryForm validation', () => {
  // Braces matter: a function returned from beforeEach runs as its cleanup,
  // and mockReset returns the mock — which would then be called once more.
  beforeEach(() => {
    vi.mocked(createEntry).mockReset();
  });

  it('marks an invalid macro inline, focuses it and does not submit', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByLabelText('Protein'), 'abc');
    await user.type(screen.getByLabelText('Carbs'), 'xyz');
    await user.click(screen.getByRole('button', { name: 'Track' }));

    const protein = screen.getByLabelText('Protein');
    expect(protein).toHaveAttribute('aria-invalid', 'true');
    expect(protein).toHaveAccessibleDescription('Enter a number or a sum like 2*150');
    expect(protein).toHaveFocus();
    expect(screen.getByLabelText('Carbs')).toHaveAttribute('aria-invalid', 'true');
    expect(createEntry).not.toHaveBeenCalled();

    await user.type(protein, '{backspace}');
    expect(protein).not.toHaveAttribute('aria-invalid');
  });

  it('flags an out-of-range calorie amount with the server bound', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByLabelText('Calories'), '20000');
    await user.click(screen.getByRole('button', { name: 'Track' }));
    const cal = screen.getByLabelText('Calories');
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveAccessibleDescription('Enter a value from -9999 to 9999');
    expect(createEntry).not.toHaveBeenCalled();
  });

  it('previews an expression and sends macros as evaluated integers', async () => {
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByLabelText('Calories'), '2*150');
    await user.type(screen.getByLabelText('Protein'), '2*15');
    await user.type(screen.getByLabelText('Carbs'), '40');

    expect(screen.getByLabelText('Calories')).toHaveAccessibleDescription('= 300');
    expect(screen.getByLabelText('Protein')).toHaveAccessibleDescription('= 30');
    expect(screen.queryByTestId('entry-macro-carbs-preview')).toBeNull();

    await user.click(screen.getByRole('button', { name: 'Track' }));
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ amount: 300, protein_g: 30, carbs_g: 40 }));
  });

  it('maps a server calorie-range rejection onto the calories field', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Calories must be between -9999 and 9999'));
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByLabelText('Calories'), '100');
    await user.click(screen.getByRole('button', { name: 'Track' }));
    const cal = await screen.findByRole('textbox', { name: 'Calories' });
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveFocus();
  });
});
