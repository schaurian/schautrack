import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ErrorBoundary from '@/components/ErrorBoundary';
import App from './App';
import { i18nReady } from '@/i18n';
// Self-hosted Noto Sans (weights 400/500/600/700) — replaces the third-party
// Google Fonts request for GDPR compliance and air-gapped/self-hosted support.
// All supported locales use the Latin script; Polish additionally requires
// Latin Extended. Importing explicit subsets avoids bundling unused scripts.
import '@fontsource/noto-sans/latin-400.css';
import '@fontsource/noto-sans/latin-ext-400.css';
import '@fontsource/noto-sans/latin-500.css';
import '@fontsource/noto-sans/latin-ext-500.css';
import '@fontsource/noto-sans/latin-600.css';
import '@fontsource/noto-sans/latin-ext-600.css';
import '@fontsource/noto-sans/latin-700.css';
import '@fontsource/noto-sans/latin-ext-700.css';
// Display face for titles, section labels and the ring numerals.
import '@fontsource/space-grotesk/latin-500.css';
import '@fontsource/space-grotesk/latin-ext-500.css';
import '@fontsource/space-grotesk/latin-700.css';
import '@fontsource/space-grotesk/latin-ext-700.css';
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
