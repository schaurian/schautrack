import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import type { User } from '@/types';
import MacroSettings from './MacroSettings';

vi.mock('@/api/settings', () => ({ saveMacros: vi.fn() }));

const user = {
  macrosEnabled: { calories: true, protein: true, carbs: true, fat: true, auto_calc_calories: false },
  macroGoals: { calories: 2000 },
  goalThreshold: 10,
} as unknown as User;

describe('MacroSettings threshold', () => {
  afterEach(async () => {
    await i18n.changeLanguage('en');
  });

  it('explains what the threshold does and ties it to the input', () => {
    render(<MacroSettings user={user} onSave={() => {}} />);
    const input = screen.getByDisplayValue('10');
    expect(input).toHaveAccessibleDescription(/before it shows red instead of yellow/);
  });

  describe('in German', () => {
    beforeEach(async () => {
      await i18n.changeLanguage('de');
    });

    it('translates the help text and the auto-calc formula', () => {
      render(<MacroSettings user={user} onSave={() => {}} />);
      expect(screen.getByDisplayValue('10')).toHaveAccessibleDescription(/rot statt gelb/);
      expect(screen.getByText('E×4 + K×4 + F×9')).toBeInTheDocument();
    });
  });
});
