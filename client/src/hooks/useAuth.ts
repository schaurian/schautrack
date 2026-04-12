import { useEffect } from 'react';
import { useNavigate } from 'react-router';
import { useAuthStore } from '@/stores/authStore';

export function useAuth() {
  return useAuthStore();
}

export function useRequireAuth() {
  const { user, isLoading, isInitialized } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (isInitialized && !isLoading && !user) {
      navigate('/login', { replace: true });
    }
  }, [user, isLoading, isInitialized, navigate]);

  return { user, isLoading: isLoading || !isInitialized };
}

export function useRequireAdmin() {
  const { user, isAdmin, isLoading, isInitialized } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (isInitialized && !isLoading) {
      if (!user) {
        navigate('/login', { replace: true });
      } else if (!isAdmin) {
        navigate('/dashboard', { replace: true });
      }
    }
  }, [user, isAdmin, isLoading, isInitialized, navigate]);

  return { user, isAdmin, isLoading: isLoading || !isInitialized };
}
