import { cn } from '@/lib/utils';

export interface SegmentedOption {
  value: string;
  label: string;
}

/**
 * A row of mutually exclusive options, all visible at once.
 *
 * Used where a <select> was hiding a binary choice (Limit vs Target, kg vs lb)
 * behind a tap — the options are short and few, so showing them beats making
 * someone open a picker to discover what the alternative even is.
 *
 * Implemented as a radiogroup rather than a listbox: arrow keys move between
 * options and only the checked one is a tab stop, which is what the WAI-ARIA
 * radio pattern specifies and what a native radio group already does.
 */
export function SegmentedControl({
  value,
  onChange,
  options,
  name,
  disabled,
  className,
  'aria-label': ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  options: SegmentedOption[];
  name?: string;
  disabled?: boolean;
  className?: string;
  'aria-label'?: string;
}) {
  const move = (dir: 1 | -1) => {
    const i = options.findIndex((o) => o.value === value);
    const next = options[(i + dir + options.length) % options.length];
    if (next) onChange(next.value);
  };

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      data-testid={name ? `segmented-${name}` : undefined}
      className={cn(
        'inline-flex items-center gap-0.5 rounded-[10px] border border-white/10 bg-white/[0.04] p-0.5',
        disabled && 'pointer-events-none opacity-50',
        className,
      )}
      onKeyDown={(e) => {
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); move(1); }
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      }}
    >
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            disabled={disabled}
            onClick={() => onChange(o.value)}
            className={cn(
              'cursor-pointer rounded-[8px] border-none px-2.5 py-1.5 text-xs font-semibold transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50',
              active
                ? 'bg-primary/15 text-primary'
                : 'bg-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export default SegmentedControl;
