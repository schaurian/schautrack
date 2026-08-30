import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ErrorBoundary from '@/components/ErrorBoundary';
import App from './App';
import { i18nReady } from '@/i18n';
// Self-hosted Noto Sans (weights 400/500/600/700) and Space Grotesk (500/700) —
// replaces the third-party Google Fonts request for GDPR compliance and
// air-gapped/self-hosted support. Latin and Latin Extended only; see the header
// of fonts.css for why the @font-face rules are declared there rather than
// imported from @fontsource directly.
import '@/styles/fonts.css';
import '@/styles/global.css';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

// Do not paint the fallback English UI before a returning user's stored
// language has been loaded. Subsequent changes are handled by the backend
// above and react-i18next re-renders once their namespace chunks arrive.
void i18nReady.then(() => {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index.html always ships #root; if it is missing, crashing at boot is the honest failure
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
});
