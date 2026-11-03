import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
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
import { createSavedFood } from '@/api/savedFoods';
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

  it('reads "12,5" as twelve and a half in German and previews what is saved', async () => {
    await i18n.changeLanguage('de');
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-fat'), '12,5');
    await user.type(field('entry-calories'), '250');
    // Rounded on save, so the preview says so.
    expect(screen.getByTestId('entry-macro-fat-preview')).toHaveTextContent('= 13');
    expect(screen.queryByTestId('entry-calories-preview')).toBeNull();
    await user.click(track());
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ amount: 250, fat_g: 13 }));
  });

  // "1.200" in German: 1200 with a thousands dot, or 1.2 typed from a keypad?
  it('refuses a thousands-shaped dot number in German with both readings', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-calories'), '1.200');
    expect(screen.queryByTestId('entry-calories-preview')).toBeNull();
    await user.click(track());
    const cal = field('entry-calories');
    expect(cal).toHaveAttribute('aria-invalid', 'true');
    expect(cal).toHaveAccessibleDescription('Schreib 1200 oder 1,200 für eine Dezimalzahl');
    expect(createEntry).not.toHaveBeenCalled();
  });

  it('previews the saved value with the quantity applied', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-fat'), '12.5');
    expect(screen.getByTestId('entry-macro-fat-preview')).toHaveTextContent('= 13');
    await user.click(screen.getByRole('button', { name: 'Increase quantity' }));
    expect(screen.getByTestId('entry-macro-fat-preview')).toHaveTextContent('= 25');
  });

  // The "= n" overlay sits inside the input; the input's right padding is
  // what keeps typed text from running under it.
  it('pads the input for the preview only while one is shown', async () => {
    const user = userEvent.setup();
    renderForm();
    const protein = field('entry-macro-protein');
    await user.type(protein, '2*15');
    expect(protein.style.paddingRight).toMatch(/^calc\(.*\d+ch.*\)$/);
    await user.clear(protein);
    await user.type(protein, '30');
    expect(protein.style.paddingRight).toBe('');
  });

  it('saves a quick-add with the active language\'s decimal comma', async () => {
    await i18n.changeLanguage('de');
    vi.mocked(createSavedFood).mockResolvedValue({ ok: true } as never);
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByRole('textbox', { name: 'Name des Lebensmittels' }), 'Toast');
    await user.type(field('entry-calories'), '80,5');
    await user.type(field('entry-macro-fat'), '2,5');
    await user.click(screen.getByRole('button', { name: 'Als Schnellzugriff speichern' }));
    expect(createSavedFood).toHaveBeenCalledWith(expect.objectContaining({ name: 'Toast', amount: 81, fat_g: 3 }));
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

  it('checks auto-calculated calories with the quantity applied', async () => {
    vi.mocked(createEntry).mockResolvedValue({ ok: true });
    const user = userEvent.setup();
    renderForm({ autoCalcCalories: true });
    // 499 g each is 499*17 = 8483 kcal per serving: fine once. Twice, every
    // macro is still within 999 g but the calories (16966) are not.
    await user.type(field('entry-macro-protein'), '499');
    await user.type(field('entry-macro-carbs'), '499');
    await user.type(field('entry-macro-fat'), '499');
    await user.click(screen.getByRole('button', { name: 'Increase quantity' }));
    await user.click(track());
    const cal = field('entry-calories');
    expect(cal).toHaveAccessibleDescription('Times 2, calories from these macros exceed 9999');
    expect(createEntry).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Decrease quantity' }));
    expect(cal).not.toHaveAttribute('aria-invalid');
    await user.click(track());
    expect(createEntry).toHaveBeenCalledWith(expect.objectContaining({ protein_g: 499, carbs_g: 499, fat_g: 499 }));
  });

  it('keeps an error from the server\'s tighter bounds across a quantity change', async () => {
    vi.mocked(createEntry).mockRejectedValue(new ApiError(400, 'Macro values must be between 0 and 100'));
    const user = userEvent.setup();
    renderForm();
    await user.type(field('entry-macro-protein'), '150');
    await user.click(track());
    const protein = await screen.findByTestId('entry-macro-protein');
    expect(protein).toHaveAttribute('aria-invalid', 'true');
    await user.click(screen.getByRole('button', { name: 'Increase quantity' }));
    expect(protein).toHaveAttribute('aria-invalid', 'true');
    expect(protein).toHaveAccessibleDescription('Times 2, this must stay between 0 and 100');
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
