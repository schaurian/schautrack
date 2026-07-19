import { useEffect, useState } from 'react';
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

// SVG activity ring. With a goal: a glowing round-capped arc sweeps in on
// mount, colored by MacroStatus (green/amber/red) falling back to the macro
// color. Without a goal there is no progress semantics — just a hairline
// circle with the value, so untargeted metrics stay quiet.
// `delay` staggers the sweep so the Today dial loads as one orchestrated
// moment (calories first, then each macro).
export function Ring({ value, goal, unit, label, macroKey, status, size = 76, delay = 0 }: {
  value: number;
  goal: number | null;
  unit: string;
  label: string;
  macroKey: string;
  status: MacroStatus;
  size?: number;
  delay?: number;
}) {
  const hasGoal = goal != null && goal > 0;
  const pct = hasGoal ? ringProgress(value, goal) : 0;
  const color = ringColor(status.statusClass, macroKey);
  const large = size >= 90;
  const strokeWidth = large ? 7 : 5.5;
  const r = (size - strokeWidth - 4) / 2; // 4px breathing room for the glow
  const circumference = 2 * Math.PI * r;

  // Sweep the arc in on mount (global reduced-motion CSS neutralizes it).
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const dashOffset = circumference * (1 - (mounted ? pct : 0) / 100);

  return (
    <div
      className="flex flex-col items-center"
      role="img"
      aria-label={`${label}: ${value}${hasGoal ? ` / ${goal}` : ''} ${unit}`}
      title={status.statusText || undefined}
    >
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" aria-hidden="true">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="rgba(255,255,255,0.09)"
            strokeWidth={hasGoal ? strokeWidth : 2}
          />
          {hasGoal && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              stroke={color}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              style={{
                filter: `drop-shadow(0 0 5px ${color})`,
                transition: `stroke-dashoffset 0.9s cubic-bezier(0.22, 1, 0.36, 1) ${delay}ms`,
              }}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
          <span className={cn(
            'font-display font-bold tabular-nums',
            large ? 'text-[22px]' : 'text-[14px]',
            !hasGoal && (LABEL_COLORS[macroKey] || 'text-primary'),
          )}>{value}</span>
          {hasGoal && (
            <span className={cn('mt-0.5 tabular-nums text-muted-foreground', large ? 'text-[10px]' : 'text-[8.5px]')}>
              /{goal}{unit !== 'kcal' ? unit : ''}
            </span>
          )}
        </div>
      </div>
      <span className={cn(
        'mt-1.5 font-display font-bold uppercase tracking-[0.12em]',
        large ? 'text-[10.5px]' : 'text-[9.5px]',
        LABEL_COLORS[macroKey] || 'text-primary',
      )}>
        {label}
      </span>
    </div>
  );
}
