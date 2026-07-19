import type { MacroStatus } from '@/types';
import { ringProgress, ringColor } from '@/lib/ring';
import { cn } from '@/lib/utils';

const LABEL_COLORS: Record<string, string> = {
  kcal: 'text-macro-kcal',
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

// Conic-gradient progress ring. Center shows the value (+ goal when set);
// ring color reflects MacroStatus (green/amber/red) falling back to the macro color.
export function Ring({ value, goal, unit, label, macroKey, status, size = 76 }: {
  value: number;
  goal: number | null;
  unit: string;
  label: string;
  macroKey: string;
  status: MacroStatus;
  size?: number;
}) {
  const pct = ringProgress(value, goal);
  const color = ringColor(status.statusClass, macroKey);
  const hole = size - 14;
  return (
    <div
      className="flex flex-col items-center"
      role="img"
      aria-label={`${label}: ${value}${goal != null ? ` / ${goal}` : ''} ${unit}`}
      title={status.statusText || undefined}
    >
      <div
        className="grid place-items-center rounded-full"
        style={{ width: size, height: size, background: `conic-gradient(${color} ${pct}%, var(--color-muted) 0)` }}
      >
        <div
          className="grid place-items-center rounded-full bg-background"
          style={{ width: hole, height: hole }}
        >
          <div className="flex flex-col items-center leading-none">
            <span className="text-[15px] font-extrabold tabular-nums">{value}</span>
            {goal != null && (
              <span className="mt-0.5 text-[9px] text-muted-foreground tabular-nums">/{goal}{unit !== 'kcal' ? unit : ''}</span>
            )}
          </div>
        </div>
      </div>
      <span className={cn('mt-1.5 text-[10px] font-bold uppercase tracking-wider', LABEL_COLORS[macroKey] || 'text-primary')}>
        {label}
      </span>
    </div>
  );
}
