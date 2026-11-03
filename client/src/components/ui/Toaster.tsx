import { useLayoutEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useToastStore, type Toast } from '@/stores/toastStore';
import { cn } from '@/lib/utils';

// Which control had keyboard focus in a toast that is being replaced, keyed by
// toast id, so the remounted toast can put focus back on the same control
// instead of letting it fall to <body>.
const focusHandoff = new Map<number, string>();

export default function Toaster() {
  const toasts = useToastStore((s) => s.toasts);

  // The live-region container is always rendered so screen readers observe it
  // before toasts are inserted. Non-error toasts inherit polite; error toasts
  // override to an assertive alert.
  //
  // The stack is offset to clear the FAB so an undo action never hides under the
  // add button — the toast paints above it (z-400 vs z-60). Both offsets are the
  // FAB's own bottom plus its 3.5rem height plus a 0.75rem gap: 4.5rem up on
  // mobile (it clears the tab bar), 2rem up on desktop.
  //
  // z-[400] puts toasts above every overlay layer (add sheet z-200, Manage and
  // scanner modals z-300): at z-200 the add sheet's backdrop, later in the
  // DOM, sat over the toast and swallowed the click on Undo. pointer-events-auto
  // because an open Radix modal sets pointer-events: none on <body>, which the
  // toaster would otherwise inherit, so clicks fall through to the overlay.
  // Covered by e2e/saved-food-undo.spec.ts.
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="false"
      className="pointer-events-auto fixed right-4 z-[400] flex flex-col gap-2 max-w-sm bottom-[calc(8.75rem+env(safe-area-inset-bottom))] lg:bottom-[6.25rem]"
    >
      {toasts.map((toast) => (
        // A replaced toast (same replace key, e.g. a second entry deleted) gets
        // a new React key so it remounts: the live region announces it again
        // and the replace animation plays from the start instead of the
        // slide-in, signalling that another one went.
        <ToastItem key={`${toast.id}:${toast.revision}`} toast={toast} />
      ))}
    </div>
  );
}

function ToastItem({ toast }: { toast: Toast }) {
  const { t } = useTranslation('common');
  const removeToast = useToastStore((s) => s.removeToast);
  const pauseToast = useToastStore((s) => s.pauseToast);
  const resumeToast = useToastStore((s) => s.resumeToast);
  const ref = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    const control = focusHandoff.get(toast.id);
    if (control !== undefined) {
      focusHandoff.delete(toast.id);
      el?.querySelector<HTMLElement>(`[data-toast-control="${control}"]`)?.focus();
    }
    // Layout cleanup runs before React detaches this node, so focus is still
    // observable here. Only hand it off when the toast lives on (replaced),
    // not when it is being dismissed.
    return () => {
      const active = document.activeElement;
      if (!el || !(active instanceof HTMLElement) || !el.contains(active)) return;
      if (!useToastStore.getState().toasts.some((t) => t.id === toast.id)) return;
      focusHandoff.set(toast.id, active.dataset.toastControl ?? 'dismiss');
    };
  }, [toast.id]);

  return (
    <div
      ref={ref}
      role={toast.type === 'error' ? 'alert' : undefined}
      aria-live={toast.type === 'error' ? 'assertive' : undefined}
      onMouseEnter={() => pauseToast(toast.id)}
      onMouseLeave={() => resumeToast(toast.id)}
      onFocus={() => pauseToast(toast.id)}
      onBlur={() => resumeToast(toast.id)}
      className={cn(
        'flex items-center gap-3 rounded-md border px-4 py-3 text-sm shadow-lg',
        toast.revision > 0 ? 'animate-toast-replace' : 'animate-in slide-in-from-right-5 fade-in',
        toast.type === 'success' && 'bg-card border-success/30 text-green-400',
        toast.type === 'error' && 'bg-card border-destructive/30 text-red-400',
        toast.type === 'info' && 'bg-card border-[#0ea5e9]/30 text-[#0ea5e9]',
      )}
    >
      <span className="flex-1">{toast.message}</span>
      {toast.action && (
        <button
          type="button"
          data-toast-control="action"
          className="bg-transparent border border-current/50 rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wider cursor-pointer hover:bg-current/10 transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            toast.action?.onClick();
            removeToast(toast.id);
          }}
        >
          {toast.action.label}
        </button>
      )}
      <button
        type="button"
        data-toast-control="dismiss"
        aria-label={t('toaster.dismiss')}
        className="bg-transparent border-0 text-muted-foreground hover:text-foreground cursor-pointer text-lg leading-none p-0"
        onClick={() => removeToast(toast.id)}
      >&times;</button>
    </div>
  );
}
