import { cn } from '@/lib/utils';

// Floating action button — mobile only, sits above the bottom tab bar.
export function Fab({ onClick, className, 'aria-label': ariaLabel }: {
  onClick: () => void;
  className?: string;
  'aria-label': string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
      className={cn(
        'fixed bottom-[calc(4.5rem+env(safe-area-inset-bottom))] right-4 z-[60] grid size-14 cursor-pointer place-items-center rounded-2xl',
        'bg-gradient-to-br from-secondary to-primary text-primary-foreground shadow-[0_6px_24px_rgba(109,140,255,0.45)]',
        'transition-transform active:scale-95 lg:hidden',
        className,
      )}
    >
      <svg aria-hidden="true" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
        <path d="M12 5v14" /><path d="M5 12h14" />
      </svg>
    </button>
  );
}
