import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import Landing from './Landing';

describe('Landing images', () => {
  it('provides the Google Play badge intrinsic dimensions', () => {
    render(
      <MemoryRouter>
        <Landing />
      </MemoryRouter>,
    );

    const badge = screen.getByRole('img', { name: 'Get it on Google Play' });
    expect(badge).toHaveAttribute('width', '646');
    expect(badge).toHaveAttribute('height', '250');
  });
});
