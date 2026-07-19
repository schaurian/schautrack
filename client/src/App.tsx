import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { useDashboardStore } from '@/stores/dashboardStore';
import { useSSE } from '@/hooks/useSSE';
import { setOn401 } from '@/api/client';
import { queryClient } from './main';
import Toaster from '@/components/ui/Toaster';
import StepUpModal from '@/components/StepUpModal';
import AppRouter from './router';
import i18n, { isSupportedLanguage } from '@/i18n';

export default function App() {
  const { fetchUser, isInitialized, user, clearUser } = useAuthStore();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;

  // Wire up global 401 handler — clears auth, cache, and redirects to login
  // Only redirect if the user was previously authenticated (session expired)
  useEffect(() => {
    setOn401(() => {
      const wasAuthenticated = useAuthStore.getState().isInitialized && useAuthStore.getState().user !== null;
      clearUser();
      queryClient.clear();
      useDashboardStore.getState().reset();
      if (wasAuthenticated) {
        navigateRef.current('/login', { replace: true });
      }
    });
  }, [clearUser]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  // Apply the logged-in user's explicit language preference. When it's null
  // ("Automatic"), leave i18next's browser detection in charge.
  useEffect(() => {
    const pref = user?.language;
    if (pref && isSupportedLanguage(pref) && i18n.language !== pref) {
      i18n.changeLanguage(pref);
    }
  }, [user?.language]);

  // Only connect SSE when authenticated
  return (
    <>
      {user && <SSEProvider />}
      <Toaster />
      <StepUpModal />
      {isInitialized ? <AppRouter /> : <LoadingScreen />}
    </>
  );
}

function SSEProvider() {
  useSSE();
  return null;
}

function LoadingScreen() {
  const { t } = useTranslation('common');
  return (
    <div className="flex h-screen items-center justify-center bg-background text-foreground">
      <div className="text-center">
        <div className="text-2xl font-semibold">{t('app.name')}</div>
        <div className="mt-2 text-muted-foreground">{t('app.loading')}</div>
      </div>
    </div>
  );
}
