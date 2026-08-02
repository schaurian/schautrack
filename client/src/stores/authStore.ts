import { create } from 'zustand';
import type { User } from '@/types';
import { getMe } from '@/api/auth';

interface AuthState {
  user: User | null;
  isAdmin: boolean;
  pendingLinkRequests: number;
  isLoading: boolean;
  isInitialized: boolean;
  fetchUser: () => Promise<void>;
  setUser: (user: User | null, isAdmin?: boolean) => void;
  clearUser: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isAdmin: false,
  pendingLinkRequests: 0,
  isLoading: true,
  isInitialized: false,

  fetchUser: async () => {
    // Only the very first fetch may flip the app into a loading state. Pages
    // gate their whole tree on it, so doing this for a background refresh
    // (every autosave calls fetchUser) unmounts the form mid-edit: pending
    // debounced saves are dropped and the freshly saved value visibly
    // reverts when the form remounts from the not-yet-updated query cache.
    if (!get().user) set({ isLoading: true });
    try {
      const data = await getMe();
      set({ user: data.user, isAdmin: data.isAdmin, pendingLinkRequests: data.pendingLinkRequests || 0, isLoading: false, isInitialized: true });
    } catch {
      set({ user: null, isAdmin: false, pendingLinkRequests: 0, isLoading: false, isInitialized: true });
    }
  },

  setUser: (user, isAdmin = false) => set({ user, isAdmin, isLoading: false, isInitialized: true }),
  clearUser: () => set({ user: null, isAdmin: false, pendingLinkRequests: 0, isLoading: false }),
}));
