import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import { useToastStore } from '@/stores/toastStore';
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

const field = (id: string) => screen.getByTestId(id);
const track = () => screen.getByRole('button', { name: /^(Track|Tracken)$/ });

describe('EntryForm validation', () => {
  // Braces matter: a function returned from beforeEach runs as its cleanup,
  // and mockReset returns the mock — which would then be called once more.
  beforeEach(() => {
    vi.mocked(createEntry).mockReset();
    useToastStore.setState({ toasts: [] });
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('marks an invalid macro inline, focuses it and does not submit', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByLabelText('Protein'), 'abc');
    await user.type(screen.getByLabelText('Carbs'), 'xyz');
    await user.click(track());

    const protein = screen.getByLabelText('Protein');
    expect(protein).toHaveAttribute('aria-invalid', 'true');
    expect(protein).toHaveAccessibleDescription('Enter a number or a calculation like 2*150');
    expect(protein).toHaveFocus();
    expect(screen.getByLabelText('Carbs')).toHaveAttribute('aria-invalid', 'true');
    expect(createEntry).not.toHaveBeenCalled();

    await user.type(protein, '{backspace}');
    expect(protein).not.toHaveAttribute('aria-invalid');
  });

  it('flags an out-of-range calorie amount and clears it on edit', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-calories'), '20000');
    await user.click(track());
    const cal = field('entry-calories');
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveAccessibleDescription('Enter a value from -9999 to 9999');
    expect(createEntry).not.toHaveBeenCalled();

    await user.type(cal, '{backspace}');
    expect(cal).not.toHaveAttribute('aria-invalid');
  });

  it('names the quantity in a range error and re-checks it when the quantity changes', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-protein'), '600');
    await user.click(screen.getByRole('button', { name: 'Increase quantity' }));
    await user.click(track());
    const protein = field('entry-macro-protein');
    expect(protein).toHaveAccessibleDescription('Times 2, this must stay between 0 and 999');
    expect(createEntry).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Decrease quantity' }));
    expect(protein).not.toHaveAttribute('aria-invalid');
  });

  it('previews an expression inside the field and sends macros as evaluated integers', async () => {
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-calories'), '2*150');
    await user.type(field('entry-macro-protein'), '2*15');
    await user.type(field('entry-macro-carbs'), '40');

    expect(field('entry-calories')).toHaveAccessibleDescription('= 300');
    expect(field('entry-macro-protein')).toHaveAccessibleDescription('= 30');
    expect(screen.queryByTestId('entry-macro-carbs-preview')).toBeNull();
    // Overlaid in the input's own box, not on a line below it, so showing it
    // moves nothing (#7 of the review).
    expect(screen.getByTestId('entry-calories-preview').parentElement).toBe(field('entry-calories').parentElement);
    expect(screen.getByTestId('entry-calories-preview')).toHaveClass('absolute');

    await user.click(track());
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ amount: 300, protein_g: 30, carbs_g: 40 }));
  });

  // The "numeric" keypad has no * + . or , — the hint and the decimal comma
  // would ask for keys the phone does not show.
  it('gives macros the same phone keypad as calories', () => {
    renderForm();
    for (const id of ['entry-calories', 'entry-macro-protein', 'entry-macro-carbs', 'entry-macro-fat']) {
      expect(field(id)).toHaveAttribute('inputmode', 'tel');
    }
  });

  it('multiplies by quantity before rounding', async () => {
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-calories'), '12.5');
    await user.type(field('entry-macro-fat'), '12.5');
    await user.click(screen.getByRole('button', { name: 'Increase quantity' }));
    await user.click(track());
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ amount: 25, fat_g: 25 }));
  });

  it('reads "12,5" as twelve and a half in German', async () => {
    await i18n.changeLanguage('de');
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-fat'), '12,5');
    await user.type(field('entry-calories'), '1.000');
    expect(screen.queryByTestId('entry-macro-fat-preview')).toBeNull();
    // The dot is a decimal point in German too; the preview is what shows it.
    expect(screen.getByTestId('entry-calories-preview')).toHaveTextContent('= 1');
    await user.click(track());
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ amount: 1, fat_g: 13 }));
  });

  it('checks auto-calculated calories against the calorie limit', async () => {
    const user = userEvent.setup();
    renderForm({ autoCalcCalories: true });
    await user.type(field('entry-macro-protein'), '999');
    await user.type(field('entry-macro-carbs'), '999');
    await user.type(field('entry-macro-fat'), '999');
    await user.click(track());
    const cal = field('entry-calories');
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveAccessibleDescription('Calories from these macros exceed 9999');
    expect(createEntry).not.toHaveBeenCalled();

    await user.type(field('entry-macro-fat'), '{backspace}{backspace}{backspace}');
    expect(cal).not.toHaveAttribute('aria-invalid');
  });

  it('maps a server computed-calories rejection onto the calories field', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Calories computed from macros exceed the maximum of 9999'));
    const user = userEvent.setup();
    renderForm({ autoCalcCalories: true });
    await user.type(field('entry-macro-protein'), '10');
    await user.click(track());
    const cal = await screen.findByTestId('entry-calories');
    expect(cal).toHaveAccessibleDescription('Calories from these macros exceed 9999');
  });

  it('maps a server calorie-range rejection onto the calories field', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Calories must be between -50 and 50'));
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-calories'), '100');
    await user.click(track());
    const cal = await screen.findByTestId('entry-calories');
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveAccessibleDescription('Enter a value from -50 to 50');
    expect(cal).toHaveFocus();
  });

  it('marks only the macros outside the range a server rejection names', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Macro values must be between 0 and 100'));
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-protein'), '150');
    await user.type(field('entry-macro-carbs'), '20');
    await user.click(track());
    expect(await screen.findByTestId('entry-macro-protein')).toHaveAttribute('aria-invalid', 'true');
    expect(field('entry-macro-carbs')).not.toHaveAttribute('aria-invalid');
  });

  it('falls back to a toast when no field is outside the range the server names', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Macro values must be between 0 and 999'));
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-protein'), '15');
    await user.click(track());
    await vi.waitFor(() => expect(useToastStore.getState().toasts.map((t) => t.message)).toContain('Macro values must be between 0 and 999'));
    expect(field('entry-macro-protein')).not.toHaveAttribute('aria-invalid');
  });
});

// The dashboard's selected day can change while the add-food sheet is open —
// the midnight rollover moves "today" on. The form follows that day only until
// the user picks a date in the form; a picked date must survive the rollover.
describe('EntryForm date', () => {
  function renderWithDate(selectedDate: string) {
    const client = new QueryClient();
    const ui = (date: string) => (
      <QueryClientProvider client={client}>
        <EntryForm
          selectedDate={date}
          caloriesEnabled
          autoCalcCalories={false}
          enabledMacros={[]}
          hasAiEnabled={false}
          aiUsage={null}
          aiProviderName={null}
          barcodeEnabled={false}
          onSubmit={() => {}}
        />
      </QueryClientProvider>
    );
    const view = render(ui(selectedDate));
    return { rerender: (date: string) => view.rerender(ui(date)) };
  }
  const dateInput = () => screen.getByLabelText('Entry date') as HTMLInputElement;

  it('follows the dashboard day while the user has not touched it', () => {
    const { rerender } = renderWithDate('2026-11-03');
    expect(dateInput().value).toBe('2026-11-03');
    rerender('2026-11-04');
    expect(dateInput().value).toBe('2026-11-04');
  });

  it('keeps a date the user picked when the dashboard day rolls over', () => {
    const { rerender } = renderWithDate('2026-11-03');
    fireEvent.change(dateInput(), { target: { value: '2026-11-01' } });
    rerender('2026-11-04');
    expect(dateInput().value).toBe('2026-11-01');
  });
});
