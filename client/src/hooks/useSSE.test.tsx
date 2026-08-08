import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useSSE } from './useSSE';

// The stores and i18n are stubbed because none of them participate in the
// behaviour under test — `entry-change` only revalidates queries — and
// importing the real ones drags in network calls and catalog loading.
vi.mock('@/stores/toastStore', () => ({
  useToastStore: (sel: (s: { addToast: () => void }) => unknown) => sel({ addToast: () => {} }),
}));
vi.mock('@/stores/authStore', () => ({
  useAuthStore: (sel: (s: { fetchUser: () => void }) => unknown) => sel({ fetchUser: () => {} }),
}));
vi.mock('@/i18n', () => ({ default: { t: (k: string) => k } }));

// Minimal EventSource stand-in. jsdom has none, and the real one would need a
// server; all the hook needs is addEventListener plus a way for the test to
// deliver an event.
class FakeEventSource {
  static last: FakeEventSource | null = null;
  listeners = new Map<string, ((e: MessageEvent) => void)[]>();
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;

  constructor(public url: string) {
    FakeEventSource.last = this;
  }
  addEventListener(type: string, fn: (e: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data: unknown = {}) {
    for (const fn of this.listeners.get(type) ?? []) {
      fn(new MessageEvent(type, { data: JSON.stringify(data) }));
    }
  }
}

describe('useSSE revalidation during an initial fetch', () => {
  beforeEach(() => {
    (globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;
    FakeEventSource.last = null;
  });

  afterEach(() => {
    delete (globalThis as unknown as { EventSource?: unknown }).EventSource;
  });

  // The regression. query-core's Query.fetch() only honours cancelRefetch once
  // the query holds data:
  //
  //   if (this.state.data !== undefined && fetchOptions?.cancelRefetch) {
  //     this.cancel({ silent: true });
  //   } else if (this.#retryer) {
  //     return this.#retryer.promise;   // deduped into the in-flight request
  //   }
  //
  // So an invalidation that lands while a query is still running its FIRST
  // request is folded into that already-issued request, and its success then
  // clears isInvalidated — leaving the tab on pre-event data with no refetch
  // pending. A second tab hits this whenever an event arrives during its first
  // render, which is exactly when a realtime update matters most.
  //
  // Reverting useSSE to a bare invalidateQueries() fails this test with
  // "dashboard v1", the value fetched before the event.
  it('refetches a query whose very first request is still in flight', async () => {
    let resolveFirst: ((v: string) => void) | undefined;
    let call = 0;

    const queryFn = vi.fn(() => {
      call += 1;
      if (call === 1) {
        return new Promise<string>((res) => {
          resolveFirst = res;
        });
      }
      return Promise.resolve(`dashboard v${call}`);
    });

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    });

    function Dashboard() {
      useSSE();
      const { data } = useQuery({ queryKey: ['dashboard'], queryFn });
      return <div data-testid="value">{data ?? 'loading'}</div>;
    }

    render(
      <QueryClientProvider client={queryClient}>
        <Dashboard />
      </QueryClientProvider>,
    );

    // The stream is open and the first request is still outstanding — the exact
    // window a second tab sits in while it hydrates.
    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());
    expect(queryFn).toHaveBeenCalledTimes(1);

    FakeEventSource.last!.emit('entry-change');

    // Only now does the pre-event request come back. Its value is stale by
    // definition: it was issued before the event that invalidated it.
    resolveFirst!('dashboard v1');

    await waitFor(() => {
      expect(screen.getByTestId('value')).toHaveTextContent('dashboard v2');
    });
    expect(queryFn).toHaveBeenCalledTimes(2);

    queryClient.clear();
  });

  it('still revalidates a query that already holds data', async () => {
    const queryFn = vi.fn().mockResolvedValueOnce('first').mockResolvedValueOnce('second');
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    });

    function Dashboard() {
      useSSE();
      const { data } = useQuery({ queryKey: ['dashboard'], queryFn });
      return <div data-testid="value">{data ?? 'loading'}</div>;
    }

    render(
      <QueryClientProvider client={queryClient}>
        <Dashboard />
      </QueryClientProvider>,
    );

    await waitFor(() => expect(screen.getByTestId('value')).toHaveTextContent('first'));
    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());

    FakeEventSource.last!.emit('entry-change');

    await waitFor(() => expect(screen.getByTestId('value')).toHaveTextContent('second'));
    queryClient.clear();
  });

  it('closes the stream on unmount', async () => {
    const queryClient = new QueryClient();
    const { unmount } = render(
      <QueryClientProvider client={queryClient}>
        <SseOnly />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());
    const source = FakeEventSource.last!;
    unmount();
    expect(source.closed).toBe(true);
  });
});

function SseOnly() {
  useSSE();
  return null;
}
