import { cn } from '@/lib/utils';

// Small uppercase section header used instead of card headers app-wide.
export function SectionLabel({ children, right, className }: {
  children: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-2 px-1 pb-1.5 pt-4', className)}>
      <h3 className="font-display text-[11px] font-bold uppercase tracking-[0.1em] text-muted-foreground">{children}</h3>
      {right}
    </div>
  );
}
