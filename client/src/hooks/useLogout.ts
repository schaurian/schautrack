import { useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '@/stores/authStore';
import { useDashboardStore } from '@/stores/dashboardStore';
import { logout } from '@/api/auth';

// 1. Network logout, then 2. clear all client state so the previous
// account's data can't leak into the next login in this tab, then 3. navigate.
export function useLogout() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const clearUser = useAuthStore((s) => s.clearUser);
  return async () => {
    try { await logout(); } catch { /* ignore */ }
    queryClient.clear();
    useDashboardStore.getState().reset();
    clearUser();
    navigate('/login');
  };
}
