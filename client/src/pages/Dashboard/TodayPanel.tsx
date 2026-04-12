import type { MacroStatus } from '@/types';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';
import { cn } from '@/lib/utils';

interface Props {
  dailyGoal: number | null;
  todayTotal: number;
  caloriesEnabled: boolean;
  calorieStatus: MacroStatus;
  enabledMacros: string[];
  macroGoals: Record<string, number>;
  todayMacroTotals: Record<string, number>;
  macroStatuses: Record<string, MacroStatus>;
  macroModes: Record<string, string>;
}

const LABEL_COLORS: Record<string, string> = {
  kcal: 'text-macro-kcal',
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

const BAR_COLORS: Record<string, string> = {
  kcal: 'bg-macro-kcal',
  protein: 'bg-macro-protein',
  carbs: 'bg-macro-carbs',
  fat: 'bg-macro-fat',
  fiber: 'bg-macro-fiber',
  sugar: 'bg-macro-sugar',
};

function statusClasses(statusClass: string) {
  if (statusClass === 'macro-stat--success') return { chip: 'bg-success/10 border-success/35', value: 'text-green-300', bar: 'bg-green-500' };
  if (statusClass === 'macro-stat--warning') return { chip: 'bg-warning/10 border-warning/35', value: 'text-yellow-300', bar: 'bg-amber-500' };
  if (statusClass === 'macro-stat--danger') return { chip: 'bg-destructive/10 border-destructive/35', value: 'text-red-300', bar: 'bg-red-500' };
  return { chip: 'bg-surface border-white/6', value: '', bar: '' };
}

export default function TodayPanel({
  dailyGoal, todayTotal, caloriesEnabled, calorieStatus,
  enabledMacros, macroGoals, todayMacroTotals, macroStatuses,
}: Props) {
  if (!caloriesEnabled && enabledMacros.length === 0) {
    return (
      <p className="text-center text-sm text-muted-foreground py-6">
        No nutrients tracked. <a href="/settings">Enable tracking in settings.</a>
      </p>
    );
  }

  const itemCount = (caloriesEnabled ? 1 : 0) + enabledMacros.length;
  const cols = itemCount <= 3 ? itemCount : Math.ceil(itemCount / 2);

  return (
    <section className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">Today</h3>
      </div>
      <div className="p-4 grid gap-2" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
        {caloriesEnabled && (
          <MacroChip
            macroKey="kcal"
            label="Calories"
            total={todayTotal}
            goal={dailyGoal}
            unit="kcal"
            status={calorieStatus}
          />
        )}

        {enabledMacros.map((key) => {
          const total = todayMacroTotals[key] || 0;
          const goal = macroGoals[key] ?? null;
          const status = macroStatuses[key] || { statusClass: '', statusText: '' };
          const label = MACRO_LABELS[key as MacroKey]?.label || key;

          return (
            <MacroChip
              key={key}
              macroKey={key}
              label={label}
              total={total}
              goal={goal}
              unit="g"
              status={status}
            />
          );
        })}
      </div>
    </section>
  );
}

function MacroChip({ macroKey, label, total, goal, unit, status }: {
  macroKey: string;
  label: string;
  total: number;
  goal: number | null;
  unit: string;
  status: MacroStatus;
}) {
  const pct = goal ? Math.min(Math.round((total / goal) * 100), 100) : null;
  const sc = statusClasses(status.statusClass);
  const hasStatus = !!status.statusClass;

  return (
    <div className={cn('rounded-xl border p-3 transition-colors', sc.chip)}>
      <div className={cn('text-xs font-bold uppercase tracking-wider mb-1', LABEL_COLORS[macroKey] || 'text-primary')}>
        {label}
      </div>
      <div className={cn('text-xl font-bold tabular-nums leading-tight whitespace-nowrap', hasStatus && sc.value)}>
        {total}
        {goal != null && <span className="text-muted-foreground font-normal text-[0.6em]"> / {goal} {unit}</span>}
      </div>
      {pct != null && (
        <div className="mt-2 h-2 rounded-full bg-white/10 overflow-hidden">
          <div
            className={cn('h-full rounded-full transition-[width] duration-300', hasStatus ? sc.bar : (BAR_COLORS[macroKey] || 'bg-primary'))}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
      <div className="mt-2 text-sm text-muted-foreground">{status.statusText}</div>
    </div>
  );
}
