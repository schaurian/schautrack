import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { User } from '@/types';
import { useAuthStore } from '@/stores/authStore';
import { useOnboardingStore } from '@/stores/onboardingStore';
import WelcomeTour from './WelcomeTour';

vi.mock('@/api/onboarding', () => ({ completeOnboarding: vi.fn(() => Promise.resolve()) }));

// A new account finished the tour on a bare "0 calories" ring: no goal, and
// nothing pointing at where to set one. The last step now offers it.

function setUser(goals: Partial<User>) {
  useAuthStore.setState({
    user: {
      id: 1,
      email: 'new@example.com',
      onboardingCompleted: true,
      dailyGoal: null,
      macrosEnabled: { calories: true },
      macroGoals: {},
      ...goals,
    } as User,
  });
}

async function renderAtLastStep() {
  useOnboardingStore.setState({ open: true });
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="/dashboard" element={<WelcomeTour />} />
        <Route path="/settings" element={<p>settings page</p>} />
      </Routes>
    </MemoryRouter>,
  );
  for (let i = 0; i < 4; i++) await userEvent.click(screen.getByTestId('welcome-tour-next'));
  expect(screen.getByText('5 of 5')).toBeInTheDocument();
}

describe('WelcomeTour goal step', () => {
  beforeEach(() => useOnboardingStore.setState({ open: false }));

  it('ends with "Set your goal" for an account without a calorie goal', async () => {
    setUser({});
    await renderAtLastStep();
    await userEvent.click(screen.getByRole('button', { name: 'Set your goal' }));
    expect(screen.getByText('settings page')).toBeInTheDocument();
    expect(useOnboardingStore.getState().open).toBe(false);
  });

  it('does not offer it once a goal exists', async () => {
    setUser({ macroGoals: { calories: 2200 } });
    await renderAtLastStep();
    expect(screen.queryByTestId('welcome-tour-set-goal')).toBeNull();
    expect(screen.getByTestId('welcome-tour-next')).toHaveTextContent('Start tracking');
  });

  it('does not offer it when calories are switched off', async () => {
    setUser({ macrosEnabled: { calories: false } });
    await renderAtLastStep();
    expect(screen.queryByTestId('welcome-tour-set-goal')).toBeNull();
  });
});
