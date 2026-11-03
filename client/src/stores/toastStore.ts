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
  /** Toasts sharing a replace key hold one slot: a newer one takes it over. */
  replaceKey?: string;
  /** Bumped each time the slot is taken over, so the Toaster can animate it. */
  revision: number;
}

export interface ToastOptions {
  /**
   * One toast per key: a new toast with the same key replaces the visible one
   * (content swapped, timer restarted) instead of stacking under it.
   */
  replaceKey?: string;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: ToastType, message: string, action?: ToastAction, options?: ToastOptions) => void;
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
    addToast: (type, message, action, options) => {
      const replaceKey = options?.replaceKey;
      const duration = type === 'error' || action ? LONG_DURATION : DEFAULT_DURATION;
      // A keyed toast takes over the slot of the one already on screen. Deleting
      // entries in a row shows only the latest delete and its Undo; the earlier
      // writes are already committed and simply lose their Undo.
      if (replaceKey !== undefined) {
        const existing = get().toasts.find((t) => t.replaceKey === replaceKey);
        if (existing) {
          clear(existing.id);
          set((state) => ({
            toasts: state.toasts.map((t) =>
              t.id === existing.id ? { ...t, type, message, action, duration, revision: t.revision + 1 } : t,
            ),
          }));
          schedule(existing.id, duration);
          return;
        }
      }
      // Repeated identical notices refresh the one on screen instead of
      // stacking. Autosave fires one per change, so editing three settings in a
      // row would otherwise leave three copies of "Saved" piled up. Toasts with
      // an action are exempt: each carries its own Undo for a different write.
      if (!action && replaceKey === undefined) {
        const existing = get().toasts.find(
          (t) => t.type === type && t.message === message && !t.action && t.replaceKey === undefined,
        );
        if (existing) {
          clear(existing.id);
          schedule(existing.id, existing.duration);
          return;
        }
      }
      const id = nextId++;
      set((state) => ({ toasts: [...state.toasts, { id, type, message, action, duration, replaceKey, revision: 0 }] }));
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
