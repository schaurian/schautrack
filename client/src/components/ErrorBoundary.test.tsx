import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import ErrorBoundary from './ErrorBoundary';

// ErrorBoundary is the component least reachable from the E2E suite and the
// one with the worst failure mode. Playwright can only exercise it by finding
// a real bug that makes a real page throw — which is precisely the situation
// where you want the boundary already proven to work. A component test can
// make a child throw on demand, which is the only practical way to assert any
// of this.
//
// What is being protected: if the boundary itself is broken, a render error
// does not produce the fallback card, it produces a blank white page with the
// whole app unmounted and no way back.

function Boom({ message }: { message: string }): React.ReactNode {
  throw new Error(message);
}

describe('ErrorBoundary', () => {
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // React logs caught render errors to console.error, and componentDidCatch
    // logs again. Silencing keeps the expected noise out of the run without
    // hiding it from the assertions below, which read the rendered output.
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

  it('renders its children when nothing throws', () => {
    render(
      <ErrorBoundary>
        <p>dashboard</p>
      </ErrorBoundary>,
    );

    expect(screen.getByText('dashboard')).toBeInTheDocument();
  });

  it('replaces a throwing subtree with the fallback instead of unmounting the page', () => {
    render(
      <ErrorBoundary>
        <Boom message="entry list exploded" />
      </ErrorBoundary>,
    );

    // The reload control is the only way out of the fallback state. If the
    // boundary rendered but this were missing, the user would be stuck.
    expect(screen.getByRole('button')).toBeInTheDocument();
    // Something must be on screen — a blank body is the failure this guards.
    expect(document.body.textContent?.trim()).not.toBe('');
  });

  it("surfaces the error's own message so the fallback is diagnosable", () => {
    render(
      <ErrorBoundary>
        <Boom message="entry list exploded" />
      </ErrorBoundary>,
    );

    expect(screen.getByText('entry list exploded')).toBeInTheDocument();
  });

  it('logs the error so a failure is recoverable from the browser console', () => {
    render(
      <ErrorBoundary>
        <Boom message="entry list exploded" />
      </ErrorBoundary>,
    );

    const loggedBoundaryError = consoleError.mock.calls.some((args: unknown[]) =>
      args.some((arg: unknown) => typeof arg === 'string' && arg.includes('React Error Boundary caught')),
    );
    expect(loggedBoundaryError).toBe(true);
  });

  it('does not render the fallback over a healthy sibling render', () => {
    // A boundary that latched into the error state permanently would break
    // every subsequent navigation. Each mount starts clean.
    const { unmount } = render(
      <ErrorBoundary>
        <Boom message="first" />
      </ErrorBoundary>,
    );
    unmount();

    render(
      <ErrorBoundary>
        <p>recovered view</p>
      </ErrorBoundary>,
    );

    expect(screen.getByText('recovered view')).toBeInTheDocument();
    expect(screen.queryByText('first')).not.toBeInTheDocument();
  });
});
