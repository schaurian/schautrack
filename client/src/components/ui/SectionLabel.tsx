import { cn } from '@/lib/utils';

// Small uppercase section header used instead of card headers app-wide.
export function SectionLabel({ children, right, className, headingId }: {
  children: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
  /** Makes the heading a programmatic focus target (e.g. after its list empties). */
  headingId?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-2 pb-2.5', className)}>
      <h2 id={headingId} tabIndex={headingId ? -1 : undefined} className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">{children}</h2>
      {right}
    </div>
  );
}
