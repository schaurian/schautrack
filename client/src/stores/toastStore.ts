import { create } from 'zustand';

interface Toast {
  id: number;
  type: 'success' | 'error';
  message: string;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: 'success' | 'error', message: string) => void;
  removeToast: (id: number) => void;
}

let nextId = 0;

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  addToast: (type, message) => {
    const id = nextId++;
    set((state) => ({ toasts: [...state.toasts, { id, type, message }] }));
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    }, 3000);
  },
  removeToast: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));
