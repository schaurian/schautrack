import { create } from 'zustand';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

type ToastType = 'success' | 'error' | 'info';

interface Toast {
  id: number;
  type: ToastType;
  message: string;
  action?: ToastAction;
  duration: number;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: ToastType, message: string, action?: ToastAction) => void;
  removeToast: (id: number) => void;
  pauseToast: (id: number) => void;
  resumeToast: (id: number) => void;
}

const DEFAULT_DURATION = 5000;
// Errors and toasts carrying an action (e.g. Undo) linger longer so users with
// motor or cognitive impairments have time to read and act on them.
const LONG_DURATION = 10000;

// Timer handles live outside the store so pausing/resuming (on hover/focus)
// doesn't trigger re-renders.
const timers = new Map<number, ReturnType<typeof setTimeout>>();

let nextId = 0;

export const useToastStore = create<ToastState>((set, get) => {
  const schedule = (id: number, duration: number) => {
    const handle = setTimeout(() => {
      timers.delete(id);
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    }, duration);
    timers.set(id, handle);
  };

  const clear = (id: number) => {
    const handle = timers.get(id);
    if (handle !== undefined) {
      clearTimeout(handle);
      timers.delete(id);
    }
  };

  return {
    toasts: [],
    addToast: (type, message, action) => {
      const id = nextId++;
      const duration = type === 'error' || action ? LONG_DURATION : DEFAULT_DURATION;
      set((state) => ({ toasts: [...state.toasts, { id, type, message, action, duration }] }));
      schedule(id, duration);
    },
    removeToast: (id) => {
      clear(id);
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    },
    // Pause auto-dismiss while the toast is hovered or focused.
    pauseToast: (id) => {
      clear(id);
    },
    // Restart the auto-dismiss timer once the pointer/focus leaves.
    resumeToast: (id) => {
      if (timers.has(id)) return;
      const toast = get().toasts.find((t) => t.id === id);
      if (toast) schedule(id, toast.duration);
    },
  };
});
