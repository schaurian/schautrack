import { cn } from '@/lib/utils';

// Small uppercase section header used instead of card headers app-wide.
export function SectionLabel({ children, right, className }: {
  children: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-2 pb-2.5', className)}>
      <h3 className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">{children}</h3>
      {right}
    </div>
  );
}
