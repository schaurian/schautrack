import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ErrorBoundary from '@/components/ErrorBoundary';
import App from './App';
import '@/styles/global.css';

// Load the Noto Sans web font stylesheet asynchronously instead of as a
// render-blocking <link> in index.html, so first paint isn't delayed by the
// DNS+TLS round trips to fonts.googleapis.com/fonts.gstatic.com. Injecting it
// from the bundle (script-src 'self') keeps the CSP intact — the inline
// media=print/onload swap would be blocked by our script-src policy.
const fontStylesheet = document.createElement('link');
fontStylesheet.rel = 'stylesheet';
fontStylesheet.href =
  'https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap';
document.head.appendChild(fontStylesheet);

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>
);
