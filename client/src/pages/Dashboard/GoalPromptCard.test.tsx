import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it } from 'vitest';
import GoalPromptCard from './GoalPromptCard';

const renderCard = (userId = 7) =>
  render(
    <MemoryRouter>
      <GoalPromptCard userId={userId} />
    </MemoryRouter>,
  );

describe('GoalPromptCard', () => {
  beforeEach(() => localStorage.clear());

  it('links to the goal setting', () => {
    renderCard();
    expect(screen.getByRole('link', { name: 'Set goal' })).toHaveAttribute('href', '/settings');
  });

  it('stays dismissed for that account after a remount', async () => {
    const { unmount } = renderCard();
    await userEvent.click(screen.getByRole('button', { name: 'Not now' }));
    expect(screen.queryByTestId('goal-prompt')).toBeNull();
    unmount();
    renderCard();
    expect(screen.queryByTestId('goal-prompt')).toBeNull();
    // A different account on the same device still gets the prompt.
    renderCard(8);
    expect(screen.getByTestId('goal-prompt')).toBeInTheDocument();
  });
});
