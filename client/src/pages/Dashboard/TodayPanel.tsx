import { useTranslation } from 'react-i18next';
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
  selectedDate: string;
  todayStr: string;
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

/**
 * Semantic status ('success' | 'warning' | 'danger') exposed as `data-status`
 * so tests can assert goal status without coupling to Tailwind color classes.
 */
function statusName(statusClass: string) {
  return statusClass.startsWith('macro-stat--') ? statusClass.slice('macro-stat--'.length) : undefined;
}

function statusClasses(statusClass: string) {
  if (statusClass === 'macro-stat--success') return { value: 'text-green-300', bar: 'bg-green-500' };
  if (statusClass === 'macro-stat--warning') return { value: 'text-yellow-300', bar: 'bg-amber-500' };
  if (statusClass === 'macro-stat--danger') return { value: 'text-red-300', bar: 'bg-red-500' };
  return { value: '', bar: '' };
}

export default function TodayPanel({
  dailyGoal, todayTotal, caloriesEnabled, calorieStatus,
  enabledMacros, macroGoals, todayMacroTotals, macroStatuses,
  selectedDate, todayStr,
}: Props) {
  const { t } = useTranslation('dashboard');
  if (!caloriesEnabled && enabledMacros.length === 0) {
    return (
      <p className="text-center text-sm text-muted-foreground py-6">
        {t('dashboard.noNutrientsTracked')} <a href="/settings">{t('dashboard.enableTrackingLink')}</a>
      </p>
    );
  }

  return (
    <section data-testid="today-panel" className="pt-1 pb-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {selectedDate === todayStr ? t('dashboard.todayLabel') : selectedDate}
      </div>

      {caloriesEnabled && (
        <HeroCalories total={todayTotal} goal={dailyGoal} status={calorieStatus} />
      )}

      {enabledMacros.length > 0 && (
        <div
          className={cn(
            'grid gap-x-5 gap-y-4 [grid-template-columns:repeat(auto-fill,minmax(86px,1fr))]',
            caloriesEnabled ? 'mt-6' : 'mt-4'
          )}
        >
          {enabledMacros.map((key) => {
            const total = todayMacroTotals[key] || 0;
            const goal = macroGoals[key] ?? null;
            const status = macroStatuses[key] || { statusClass: '', statusText: '' };
            const label = MACRO_LABELS[key as MacroKey]?.label || key;
            return (
              <MacroStat key={key} macroKey={key} label={label} total={total} goal={goal} unit="g" status={status} />
            );
          })}
        </div>
      )}
    </section>
  );
}

function HeroCalories({ total, goal, status }: { total: number; goal: number | null; status: MacroStatus }) {
  const pct = goal ? Math.min(Math.round((total / goal) * 100), 100) : null;
  const over = goal != null && total > goal;
  const sc = statusClasses(status.statusClass);
  const hasStatus = !!status.statusClass;

  return (
    <div className="mt-2" data-testid="hero-calories" data-status={statusName(status.statusClass)}>
      <div className="flex items-baseline gap-2.5">
        <span className={cn('text-6xl font-bold tabular-nums leading-none tracking-tight', hasStatus && sc.value)}>
          {total.toLocaleString()}
        </span>
        {goal != null ? (
          <span className="text-base text-muted-foreground tabular-nums">/ {goal.toLocaleString()} kcal</span>
        ) : (
          <span className="text-base text-muted-foreground">kcal</span>
        )}
      </div>

      {pct != null && (
        <div className="mt-3 h-1.5 w-full rounded-full bg-white/[0.07] overflow-hidden">
          <div
            className={cn('h-full rounded-full transition-[width] duration-500', over ? 'bg-red-500' : (hasStatus && sc.bar) || 'bg-primary')}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      {goal != null && (
        <div className="mt-1.5 text-sm text-muted-foreground tabular-nums">
          {over ? `${(total - goal).toLocaleString()} over goal` : `${(goal - total).toLocaleString()} left`}
        </div>
      )}
    </div>
  );
}

function MacroStat({ macroKey, label, total, goal, unit, status }: {
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
    <div data-testid={`macro-chip-${macroKey}`} data-status={statusName(status.statusClass)}>
      <div className={cn('text-[10px] font-semibold uppercase tracking-wider', LABEL_COLORS[macroKey] || 'text-muted-foreground')}>
        {label}
      </div>
      <div className={cn('mt-1 text-lg font-semibold tabular-nums leading-tight whitespace-nowrap', hasStatus && sc.value)}>
        {total}
        {goal != null && <span className="text-muted-foreground font-normal text-xs"> / {goal}{unit}</span>}
      </div>
      {pct != null && (
        <div className="mt-1.5 h-1 rounded-full bg-white/[0.07] overflow-hidden">
          <div
            className={cn('h-full rounded-full transition-[width] duration-300', hasStatus ? sc.bar : (BAR_COLORS[macroKey] || 'bg-primary'))}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
    </div>
  );
}
