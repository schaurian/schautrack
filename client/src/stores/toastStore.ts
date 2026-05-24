import { create } from 'zustand';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

interface Toast {
  id: number;
  type: 'success' | 'error' | 'info';
  message: string;
  action?: ToastAction;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: 'success' | 'error' | 'info', message: string, action?: ToastAction) => void;
  removeToast: (id: number) => void;
}

let nextId = 0;

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  addToast: (type, message, action) => {
    const id = nextId++;
    set((state) => ({ toasts: [...state.toasts, { id, type, message, action }] }));
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    }, 5000);
  },
  removeToast: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));
