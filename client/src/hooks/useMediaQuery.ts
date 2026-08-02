import { useSyncExternalStore } from 'react';

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const mql = window.matchMedia(query);
      mql.addEventListener('change', onChange);
      return () => mql.removeEventListener('change', onChange);
    },
    () => window.matchMedia(query).matches,
  );
}

// Matches Tailwind's `lg` breakpoint — the shell switch (sidebar vs bottom tabs).
export function useIsDesktop(): boolean {
  return useMediaQuery('(min-width: 1024px)');
}
