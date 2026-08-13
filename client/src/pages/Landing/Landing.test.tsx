import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import Landing from './Landing';

describe('Landing', () => {
  it('uses sequential heading levels for the hero and feature cards', () => {
    render(
      <MemoryRouter>
        <Landing />
      </MemoryRouter>,
    );

    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 2 })).toHaveLength(4);
    expect(screen.queryByRole('heading', { level: 3 })).not.toBeInTheDocument();
  });
});
