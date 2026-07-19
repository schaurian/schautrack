import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';
import i18n from '@/i18n';

export function useSSE() {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const fetchUser = useAuthStore((s) => s.fetchUser);
  const sourceRef = useRef<EventSource | null>(null);
  const retryDelayRef = useRef(2000);

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
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['day-entries'] });
        // The server broadcasts entry-change for weight upserts too.
        queryClient.invalidateQueries({ queryKey: ['weight'] });
      });

      source.addEventListener('settings-change', () => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        // The current user lives in the auth store, not a query.
        fetchUser();
      });

      source.addEventListener('link-change', (e) => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['settings'] });
        fetchUser();
        try {
          const data = JSON.parse((e as MessageEvent).data);
          if (data.type === 'request' && data.email) {
            addToast('info', i18n.t('notifications.linkRequestWantsToLink', { ns: 'common', email: data.email }));
          }
        } catch { /* ignore parse errors */ }
      });

      source.addEventListener('link-label-change', () => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      });

      source.addEventListener('todo-change', () => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['todos'] });
        queryClient.invalidateQueries({ queryKey: ['todos-day'] });
      });

      source.addEventListener('note-change', () => {
        queryClient.invalidateQueries({ queryKey: ['note'] });
      });

      source.addEventListener('saved-food-change', () => {
        queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
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
  }, [queryClient, fetchUser]);
}
