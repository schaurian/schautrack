import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import { useAuthStore } from '@/stores/authStore';
import type { SavedFood, User } from '@/types';
import SavedFoodsModal from './SavedFoodsModal';

// Editing a saved food's value did `Number(raw)`: "abc" or German "12,5" is
// NaN, JSON.stringify turns NaN into null, and the server cleared the column
// with a success response.

vi.mock('@/api/savedFoods', () => ({
  listSavedFoods: vi.fn(),
  createSavedFood: vi.fn(),
  updateSavedFood: vi.fn(),
  deleteSavedFood: vi.fn(),
}));

import { createSavedFood, listSavedFoods, updateSavedFood } from '@/api/savedFoods';

const food: SavedFood = {
  id: 3, name: 'Oats', emoji: null, amount: 150,
  macros: { protein: 5, carbs: 27, fat: 3, fiber: null, sugar: null },
  use_count: 0, last_used_at: null,
} as SavedFood;

function renderModal() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SavedFoodsModal isOpen onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe('SavedFoodsModal value editing', () => {
  beforeEach(() => {
    vi.mocked(listSavedFoods).mockResolvedValue({ ok: true, savedFoods: [food] });
    vi.mocked(updateSavedFood).mockReset();
    vi.mocked(updateSavedFood).mockResolvedValue({ ok: true, savedFood: food });
    vi.mocked(createSavedFood).mockReset();
    vi.mocked(createSavedFood).mockResolvedValue({ ok: true, savedFood: food });
    useAuthStore.setState({ user: { macrosEnabled: { calories: true, protein: true, carbs: true, fat: true } } as unknown as User });
  });
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  const editPill = async (user: ReturnType<typeof userEvent.setup>, label: RegExp, value: string) => {
    await user.click(await screen.findByRole('button', { name: label }));
    const input = document.activeElement as HTMLInputElement;
    await user.clear(input);
    await user.type(input, `${value}{Enter}`);
    return input;
  };

  it('never sends null for invalid input: marks it inline instead', async () => {
    const user = userEvent.setup();
    renderModal();
    const input = await editPill(user, /Calories/, 'abc');
    expect(updateSavedFood).not.toHaveBeenCalled();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Enter a number or a calculation like 2*150');
  });

  it('saves German "12,5" g as the evaluated integer', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderModal();
    await editPill(user, /Fat|Fett/, '12,5');
    expect(updateSavedFood).toHaveBeenCalledWith(3, { fat_g: 13 });
  });

  it('still clears a value on blank', async () => {
    const user = userEvent.setup();
    renderModal();
    await user.click(await screen.findByRole('button', { name: /Protein/ }));
    const input = document.activeElement as HTMLInputElement;
    await user.clear(input);
    await user.type(input, '{Enter}');
    expect(updateSavedFood).toHaveBeenCalledWith(3, { protein_g: null });
  });

  it('validates a new food\'s values before they reach the draft', async () => {
    await i18n.changeLanguage('de');
    const user = userEvent.setup();
    renderModal();
    await user.click(await screen.findByRole('button', { name: '+ Neu' }));
    await user.keyboard('Brot{Enter}');
    // The draft row's calorie pill: invalid input is held inline...
    // The draft row renders above the list, so its pill comes first.
    await user.click((await screen.findAllByRole('button', { name: /Kalorien/ }))[0]);
    const input = document.activeElement as HTMLInputElement;
    await user.type(input, '1.200{Enter}');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    // ...and a valid German decimal is handed up evaluated.
    await user.clear(input);
    await user.type(input, '80,5{Enter}');
    await user.click(screen.getByRole('button', { name: 'Hinzufügen' }));
    expect(createSavedFood).toHaveBeenCalledWith(expect.objectContaining({ name: 'Brot', amount: 81 }));
  });
});
