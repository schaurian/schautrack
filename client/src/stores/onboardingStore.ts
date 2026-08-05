import { create } from 'zustand';

/**
 * Open/closed state for the welcome tour.
 *
 * It lives in a store rather than in WelcomeTour itself because two unrelated
 * places open it: the tour auto-opens for an account that has never dismissed
 * it, and the Settings page replays it on demand. The tour is mounted once in
 * Layout, so Settings has no other way to reach it.
 */
interface OnboardingState {
  open: boolean;
  /** Replay the tour from the first step (Settings). */
  start: () => void;
  close: () => void;
}

export const useOnboardingStore = create<OnboardingState>((set) => ({
  open: false,
  start: () => set({ open: true }),
  close: () => set({ open: false }),
}));
