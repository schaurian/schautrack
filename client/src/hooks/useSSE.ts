import { useCallback, useEffect, useRef } from 'react';
import { useQueryClient, type QueryKey } from '@tanstack/react-query';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/i18n';

export function useSSE() {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const fetchUser = useAuthStore((s) => s.fetchUser);
  const sourceRef = useRef<EventSource | null>(null);
  const retryDelayRef = useRef(2000);

  /**
   * Refetch every query under `keys`, including one that is still running its
   * very first request.
   *
   * invalidateQueries() on its own silently loses that case. query-core's
   * Query.fetch() only honours cancelRefetch once the query holds data:
   *
   *   if (this.state.data !== undefined && fetchOptions?.cancelRefetch) {
   *     this.cancel({ silent: true });
   *   } else if (this.#retryer) {
   *     return this.#retryer.promise;   // deduped into the in-flight request
   *   }
   *
   * During an initial fetch (`data === undefined`) the invalidation is folded
   * into a request that was issued *before* the event, and that request's
   * success then clears isInvalidated — so the tab settles on pre-event data
   * with no refetch pending and stays wrong until something else invalidates.
   *
   * A second tab hits this whenever an event lands inside its first render,
   * which is exactly when a realtime update matters most: open the dashboard
   * twice, tick a todo in one tab while the other is still loading, and the
   * other never shows it ticked. Cancelling first puts the query back to idle,
   * so the invalidation that follows starts a genuinely new request. Cancel
   * reverts rather than discards, so a query that already had data keeps it.
   */
  const revalidate = useCallback((...keys: QueryKey[]) => {
    for (const queryKey of keys) {
      void queryClient
        .cancelQueries({ queryKey })
        .then(() => queryClient.invalidateQueries({ queryKey }));
    }
  }, [queryClient]);

  useEffect(() => {
    if (!window.EventSource) return;

    // Set on cleanup so an in-flight reconnect timer can't spawn a new
    // EventSource after unmount (e.g. after logout, when the endpoint
    // would 401 forever).
    let disposed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (disposed || sourceRef.current) return;
      const source = new EventSource('/events/entries');
      sourceRef.current = source;

      source.addEventListener('entry-change', () => {
        // The server broadcasts entry-change for weight upserts too.
        revalidate(['dashboard'], ['day-entries'], ['weight']);
      });

      source.addEventListener('settings-change', () => {
        revalidate(['dashboard']);
        // The current user lives in the auth store, not a query.
        fetchUser();
      });

      source.addEventListener('link-change', (e) => {
        revalidate(['dashboard'], ['settings']);
        fetchUser();
        try {
          const data = JSON.parse((e as MessageEvent).data);
          if (data.type === 'request' && data.email) {
            addToast('info', i18n.t('notifications.linkRequestWantsToLink', { ns: 'common', email: data.email }));
          }
        } catch { /* ignore parse errors */ }
      });

      source.addEventListener('link-label-change', () => {
        revalidate(['dashboard']);
      });

      source.addEventListener('link-shares-change', () => {
        // A permission change can add/remove whole sections from a linked
        // dashboard. Refresh both the viewer and any other open settings tab.
        revalidate(['dashboard'], ['settings']);
      });

      source.addEventListener('todo-change', () => {
        revalidate(['dashboard'], ['todos'], ['todos-day']);
      });

      source.addEventListener('note-change', () => {
        revalidate(['note']);
      });

      source.addEventListener('saved-food-change', () => {
        revalidate(['savedFoods']);
      });

      source.onopen = () => {
        retryDelayRef.current = 2000;
      };

      source.onerror = () => {
        source.close();
        sourceRef.current = null;
        if (disposed) return;
        const delay = retryDelayRef.current;
        retryDelayRef.current = Math.min(delay * 2, 30000);
        reconnectTimer = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      sourceRef.current?.close();
      sourceRef.current = null;
    };
  }, [revalidate, fetchUser]);
}
