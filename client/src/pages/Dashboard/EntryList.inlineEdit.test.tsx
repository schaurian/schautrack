import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { Entry } from '@/types';
import EntryList from './EntryList';

// Inline edit of an existing entry sent the raw text to the server, whose
// parser reads English separators: German "12,5" kcal was stored as 125.
// Macros went to the server's Atoi and failed with a toast.

vi.mock('@/api/entries', () => ({ updateEntry: vi.fn(), deleteEntry: vi.fn(), createEntry: vi.fn() }));
vi.mock('@/api/savedFoods', () => ({ saveEntryAsFood: vi.fn() }));

import { updateEntry } from '@/api/entries';

const entry: Entry = { id: 7, date: '2026-11-03', time: '12:00', amount: 200, name: 'Lunch', macros: { protein: 20, carbs: null, fat: null } };

function renderList() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <EntryList entries={[entry]} canEdit enabledMacros={['protein', 'carbs', 'fat']} caloriesEnabled autoCalcCalories={false} />
    </QueryClientProvider>,
  );
}

async function editPill(user: ReturnType<typeof userEvent.setup>, label: RegExp, value: string) {
  await user.click(screen.getByRole('button', { name: label }));
  const input = screen.getByRole('textbox');
  await user.clear(input);
  await user.type(input, `${value}{Enter}`);
  return input;
}

describe('EntryList inline edit', () => {
  beforeEach(() => {
    vi.mocked(updateEntry).mockReset();
    vi.mocked(updateEntry).mockResolvedValue({ ok: true });
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('sends German "12,5" kcal as the evaluated number, not the raw string', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderList();
    await editPill(user, /Kalorien/, '12,5');
    expect(updateEntry).toHaveBeenCalledWith(7, { amount: 13 });
  });

  it('evaluates a macro expression and a German decimal for the pill', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderList();
    await editPill(user, /Fat|Fett/, '2*7,5');
    expect(updateEntry).toHaveBeenCalledWith(7, { fat_g: 15 });
  });

  it('marks an invalid value inline, keeps editing and sends nothing', async () => {
    const user = userEvent.setup();
    renderList();
    const input = await editPill(user, /Protein/, 'abc');
    expect(updateEntry).not.toHaveBeenCalled();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Enter a number or a calculation like 2*150');

    await user.type(input, '{backspace}');
    expect(input).not.toHaveAttribute('aria-invalid');
  });

  it('refuses a thousands-shaped dot number in German', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderList();
    const input = await editPill(user, /Kalorien/, '1.200');
    expect(updateEntry).not.toHaveBeenCalled();
    expect(input).toHaveAccessibleDescription('Schreib 1200 oder 1,200 für eine Dezimalzahl');
  });

  // The "numeric" keypad has no comma, dot or operators.
  it('opens macro pills with the keypad that can type "12,5"', async () => {
    const user = userEvent.setup();
    renderList();
    await user.click(screen.getByRole('button', { name: /Protein/ }));
    expect(screen.getByRole('textbox')).toHaveAttribute('inputmode', 'tel');
  });

  it('clears the value on blank or 0, as before', async () => {
    const user = userEvent.setup();
    renderList();
    await user.click(screen.getByRole('button', { name: /Protein/ }));
    await user.clear(screen.getByRole('textbox'));
    await user.type(screen.getByRole('textbox'), '{Enter}');
    expect(updateEntry).toHaveBeenCalledWith(7, { protein_g: null });
  });
});
