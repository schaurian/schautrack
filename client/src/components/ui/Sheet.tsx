import { useEffect, useRef } from 'react';
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

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // The AI and barcode scanners open on top of this sheet and handle their
      // own Escape. This listener is on the document, so without the guard one
      // press would dismiss the scanner and the sheet under it in one go.
      // Checked in the capture phase: by the time a bubble-phase handler runs,
      // the scanner has already unmounted and there is nothing left to detect.
      if (document.querySelector('[data-modal-layer]')) return;
      onClose();
    };
    document.addEventListener('keydown', onKey, true);
    panelRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKey, true);
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

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
        {title && <h2 className="mb-3 font-display text-base font-bold">{title}</h2>}
        {children}
      </div>
    </div>,
    document.body,
  );
}
