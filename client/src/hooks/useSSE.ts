import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';

export function useSSE() {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const fetchUser = useAuthStore((s) => s.fetchUser);
  const sourceRef = useRef<EventSource | null>(null);
  const retryDelayRef = useRef(2000);

  useEffect(() => {
    if (!window.EventSource) return;

    const connect = () => {
      if (sourceRef.current) return;
      const source = new EventSource('/events/entries');
      sourceRef.current = source;

      source.addEventListener('entry-change', () => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['day-entries'] });
        queryClient.invalidateQueries({ queryKey: ['overview'] });
      });

      source.addEventListener('settings-change', () => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['me'] });
      });

      source.addEventListener('link-change', (e) => {
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
        queryClient.invalidateQueries({ queryKey: ['settings'] });
        fetchUser();
        try {
          const data = JSON.parse((e as MessageEvent).data);
          if (data.type === 'request' && data.email) {
            addToast('info', `${data.email} wants to link with you`);
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

      source.addEventListener('template-change', () => {
        queryClient.invalidateQueries({ queryKey: ['templates'] });
      });

      source.onopen = () => {
        retryDelayRef.current = 2000;
      };

      source.onerror = () => {
        source.close();
        sourceRef.current = null;
        const delay = retryDelayRef.current;
        retryDelayRef.current = Math.min(delay * 2, 30000);
        setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      sourceRef.current?.close();
      sourceRef.current = null;
    };
  }, [queryClient]);
}
