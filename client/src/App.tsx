import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router';
import { useAuthStore } from '@/stores/authStore';
import { useSSE } from '@/hooks/useSSE';
import { setOn401 } from '@/api/client';
import { queryClient } from './main';
import Toaster from '@/components/ui/Toaster';
import AppRouter from './router';

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
      if (wasAuthenticated) {
        navigateRef.current('/login', { replace: true });
      }
    });
  }, [clearUser]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  // Only connect SSE when authenticated
  return (
    <>
      {user && <SSEProvider />}
      <Toaster />
      {isInitialized ? <AppRouter /> : <LoadingScreen />}
    </>
  );
}

function SSEProvider() {
  useSSE();
  return null;
}

function LoadingScreen() {
  return (
    <div className="flex h-screen items-center justify-center bg-background text-foreground">
      <div className="text-center">
        <div className="text-2xl font-semibold">Schautrack</div>
        <div className="mt-2 text-muted-foreground">Loading...</div>
      </div>
    </div>
  );
}
