import { useEffect, useLayoutEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { cn } from '@/lib/utils';

// Bottom sheet on mobile, centered dialog on desktop. Children keep their
// state across open/close only if the parent keeps them mounted; Sheet itself
// unmounts its subtree when closed.
export function Sheet({ open, onClose, title, children }: {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  // Callers pass an inline `() => setOpen(false)`, a new function on every
  // render. Depending on it re-ran the effect below on each parent render while
  // the sheet was open — its cleanup "restored" focus to the trigger and the
  // re-run moved it back to the panel, so a refetch or an SSE echo yanked focus
  // out of the field being typed in. Read it through a ref instead.
  const onCloseRef = useRef(onClose);
  useLayoutEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    if (!open) return;
    const panel = panelRef.current;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => {
      // The AI and barcode scanners open on top of this sheet and handle their
      // own Escape and focus. This listener is on the document, so without the
      // guard one press would dismiss the scanner and the sheet under it in one
      // go. Checked in the capture phase: by the time a bubble-phase handler
      // runs, the scanner has already unmounted and there is nothing left to
      // detect.
      if (document.querySelector('[data-modal-layer]')) return;
      if (e.key === 'Escape') {
        // A popover inside the sheet (the quick-add quantity picker) is its own
        // dialog and closes itself; this capture-phase listener would otherwise
        // take the whole sheet down with it.
        const inner = (e.target as Element | null)?.closest?.('[role="dialog"]');
        if (inner && inner !== panel) return;
        onCloseRef.current();
        return;
      }
      if (e.key === 'Tab' && panel) trapTab(e, panel);
    };
    document.addEventListener('keydown', onKey, true);
    // Keyboard and screen-reader users land on the first field rather than
    // the unlabeled container: a child marks it with data-autofocus, else the
    // first tabbable element wins. Not on touch, though: focusing an input
    // there pops the on-screen keyboard over the quick-add chips, which are the
    // main mobile flow (the Android WebView). There the heading takes focus, so
    // a screen reader still starts inside the dialog with its name read out.
    const initial = isCoarsePointer()
      ? panel?.querySelector<HTMLElement>('[data-sheet-title]') ?? panel
      : panel?.querySelector<HTMLElement>('[data-autofocus]') ?? tabbables(panel)[0] ?? panel;
    initial?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKey, true);
      previouslyFocused?.focus?.();
    };
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[200]">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          'absolute inset-x-0 bottom-0 max-h-[85dvh] overflow-y-auto rounded-t-[20px] border-t border-white/10 bg-[#131b36] p-4 pb-[calc(1rem+env(safe-area-inset-bottom))] outline-none shadow-[0_-16px_60px_rgba(0,0,0,0.55)]',
          'motion-safe:animate-[sheet-up_0.25s_ease-out]',
          'lg:inset-x-auto lg:bottom-auto lg:left-1/2 lg:top-1/2 lg:w-full lg:max-w-md lg:-translate-x-1/2 lg:-translate-y-1/2 lg:rounded-2xl lg:border lg:pb-4 lg:motion-safe:animate-none',
        )}
      >
        <div className="mx-auto mb-3 h-1 w-9 rounded-full bg-border lg:hidden" aria-hidden="true" />
        {title && <h2 data-sheet-title tabIndex={-1} className="mb-3 font-display text-base font-bold outline-none">{title}</h2>}
        {children}
      </div>
    </div>,
    document.body,
  );
}

function isCoarsePointer(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(pointer: coarse)').matches;
}

const TABBABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function tabbables(root: HTMLElement | null): HTMLElement[] {
  if (!root) return [];
  return Array.from(root.querySelectorAll<HTMLElement>(TABBABLE)).filter(
    (el) => el.tabIndex >= 0 && !el.closest('[inert], [aria-hidden="true"]'),
  );
}

// aria-modal tells assistive tech the page behind is inert, so Tab must not be
// able to walk out into it either: wrap at both ends, and pull focus back in if
// it has somehow landed outside (a click on the backdrop, say). Focus inside a
// popper the sheet opened (a Radix select renders into a portal) is left alone.
function trapTab(e: KeyboardEvent, panel: HTMLElement) {
  const items = tabbables(panel);
  const active = document.activeElement as HTMLElement | null;
  if (active && !panel.contains(active) && active.closest('[data-radix-popper-content-wrapper]')) return;
  if (items.length === 0) {
    e.preventDefault();
    panel.focus();
    return;
  }
  const first = items[0];
  const last = items[items.length - 1];
  if (!active || !panel.contains(active)) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
  } else if (e.shiftKey && (active === first || !items.includes(active))) {
    // From the first field, or from a non-tabbable focus target such as the
    // heading focused on touch, Shift+Tab would otherwise leave the dialog.
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && active === last) {
    e.preventDefault();
    first.focus();
  }
}
