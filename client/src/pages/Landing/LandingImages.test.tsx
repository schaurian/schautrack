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
    // The width attribute is a CSS width hint: with only a height utility the
    // badge renders 646px wide by 56px tall. w-auto restores the aspect ratio.
    expect(badge).toHaveClass('h-14', 'w-auto');
  });
});
