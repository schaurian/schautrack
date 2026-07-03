import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

interface DashboardState {
  selectedDate: string;
  currentUserId: number | null;
  currentLabel: string;
  canEdit: boolean;
  rangePreset: number | null;
  rangeStart: string;
  rangeEnd: string;
  selectDay: (date: string) => void;
  selectUser: (userId: number, label: string, canEdit: boolean) => void;
  setRange: (preset: number | null, start: string, end: string) => void;
  reset: () => void;
}

// Initial (data-only) state. Recomputed on each call so `selectedDate`
// reflects today at reset time, not module-load time.
const initialState = (): Pick<DashboardState, 'selectedDate' | 'currentUserId' | 'currentLabel' | 'canEdit' | 'rangePreset' | 'rangeStart' | 'rangeEnd'> => ({
  // Local calendar date, not UTC — toISOString would be yesterday/tomorrow
  // around midnight for non-UTC users. The server-provided timezone date
  // still overrides this after the first dashboard fetch.
  selectedDate: new Date().toLocaleDateString('en-CA'),
  currentUserId: null,
  currentLabel: 'You',
  canEdit: true,
  rangePreset: 14,
  rangeStart: '',
  rangeEnd: '',
});

export const useDashboardStore = create<DashboardState>()(
  persist(
    (set) => ({
      ...initialState(),

      selectDay: (date) => set({ selectedDate: date }),
      selectUser: (userId, label, canEdit) => set({ currentUserId: userId, currentLabel: label, canEdit }),
      setRange: (preset, start, end) => set({ rangePreset: preset, rangeStart: start, rangeEnd: end }),
      // Restore all data fields to their initial values. Called on logout /
      // session expiry so no account's currentUserId or dashboard state leaks
      // into the next login in the same tab. Clears the persisted range too.
      reset: () => set(initialState()),
    }),
    {
      name: 'schautrack.dashboard',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        rangePreset: state.rangePreset,
        rangeStart: state.rangeStart,
        rangeEnd: state.rangeEnd,
      }),
    },
  ),
);
