import { cn } from '@/lib/utils';

interface Props {
  value: number;
  onChange: (next: number) => void;
  min?: number;
  max?: number;
  className?: string;
  label?: string;
}

const MIN_DEFAULT = 1;
const MAX_DEFAULT = 99;

export function QuantityStepper({ value, onChange, min = MIN_DEFAULT, max = MAX_DEFAULT, className, label = 'Quantity' }: Props) {
  const clamp = (n: number) => Math.max(min, Math.min(max, Math.trunc(n)));
  const dec = () => onChange(clamp(value - 1));
  const inc = () => onChange(clamp(value + 1));
  const atMin = value <= min;
  const atMax = value >= max;

  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        'inline-flex h-9 select-none items-stretch overflow-hidden rounded-md border border-input bg-muted/50',
        className,
      )}
    >
      <button
        type="button"
        onClick={dec}
        disabled={atMin}
        aria-label="Decrease quantity"
        className="px-3 text-foreground/80 transition-colors hover:bg-white/[0.06] hover:text-foreground disabled:opacity-30 disabled:hover:bg-transparent disabled:cursor-not-allowed cursor-pointer bg-transparent"
      >
        −
      </button>
      <div className="flex min-w-[2.5rem] items-center justify-center px-1 text-sm font-medium tabular-nums text-foreground">
        {value}×
      </div>
      <button
        type="button"
        onClick={inc}
        disabled={atMax}
        aria-label="Increase quantity"
        className="px-3 text-foreground/80 transition-colors hover:bg-white/[0.06] hover:text-foreground disabled:opacity-30 disabled:hover:bg-transparent disabled:cursor-not-allowed cursor-pointer bg-transparent"
      >
        +
      </button>
    </div>
  );
}

export default QuantityStepper;
