import { create } from 'zustand';
import type { User } from '@/types';
import { getMe } from '@/api/auth';

interface AuthState {
  user: User | null;
  isAdmin: boolean;
  isLoading: boolean;
  isInitialized: boolean;
  fetchUser: () => Promise<void>;
  setUser: (user: User | null, isAdmin?: boolean) => void;
  clearUser: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAdmin: false,
  isLoading: true,
  isInitialized: false,

  fetchUser: async () => {
    set({ isLoading: true });
    try {
      const data = await getMe();
      set({ user: data.user, isAdmin: data.isAdmin, isLoading: false, isInitialized: true });
    } catch {
      set({ user: null, isAdmin: false, isLoading: false, isInitialized: true });
    }
  },

  setUser: (user, isAdmin = false) => set({ user, isAdmin, isLoading: false, isInitialized: true }),
  clearUser: () => set({ user: null, isAdmin: false, isLoading: false }),
}));
