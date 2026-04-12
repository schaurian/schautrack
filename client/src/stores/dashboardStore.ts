import { create } from 'zustand';

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
}

export const useDashboardStore = create<DashboardState>((set) => ({
  selectedDate: new Date().toISOString().slice(0, 10),
  currentUserId: null,
  currentLabel: 'You',
  canEdit: true,
  rangePreset: 14,
  rangeStart: '',
  rangeEnd: '',

  selectDay: (date) => set({ selectedDate: date }),
  selectUser: (userId, label, canEdit) => set({ currentUserId: userId, currentLabel: label, canEdit }),
  setRange: (preset, start, end) => set({ rangePreset: preset, rangeStart: start, rangeEnd: end }),
}));
