import { useTranslation } from 'react-i18next';
import type { MacroStatus } from '@/types';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';
import { ringProgress, ringColor } from '@/lib/ring';
import { Ring } from '@/components/ui/Ring';
import { cn } from '@/lib/utils';
import { goalDelta, type GoalDelta } from '@/lib/goalFeedback';

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
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

/** "480 left" / "+24 over" / "30 to go" / "Goal met", localized. */
function useDeltaText() {
  const { t } = useTranslation('dashboard');
  const { t: tc } = useTranslation('common');
  return (d: GoalDelta) => {
    switch (d.kind) {
      case 'left': return t('today.left', { amount: d.amount });
      case 'over': return t('today.over', { amount: d.amount });
      case 'toGo': return t('today.toGo', { amount: d.amount });
      case 'met': return tc('macros.goalMet');
    }
  };
}

// One glowing bar per macro — easier to compare against each other than
// mini-rings; the big calorie ring keeps the single budget number focal.
// Past the goal the bar rescales so the goal sits at goal/total of the width:
// a tick marks the goal and the overshoot beyond it is hatched, so 134/110
// no longer looks the same as 110/110.
function MacroBar({ macroKey, label, value, goal, mode, status }: {
  macroKey: string;
  label: string;
  value: number;
  goal: number | null;
  mode: string;
  status: MacroStatus;
}) {
  const deltaText = useDeltaText();
  const hasGoal = goal != null && goal > 0;
  const pct = hasGoal ? ringProgress(value, goal) : 0;
  const color = ringColor(status.statusClass, macroKey);
  const delta = goalDelta(value, goal, mode);
  const over = delta?.kind === 'over';
  const goalPct = over && goal ? (goal / value) * 100 : 100;
  const text = delta ? deltaText(delta) : '';
  return (
    <div
      role="img"
      aria-label={`${label}: ${value}${hasGoal ? ` / ${goal}` : ''} g${text ? `, ${text}` : ''}`}
      title={status.statusText || undefined}
    >
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[12px] leading-none">
        <span className={cn('font-display font-bold', LABEL_COLORS[macroKey] || 'text-primary')}>{label}</span>
        <span className="flex items-baseline gap-1.5 tabular-nums">
          <span className="font-bold text-[#c3ccdd]">
            {value}
            <span className="font-normal text-muted-foreground">{hasGoal ? `/${goal}g` : 'g'}</span>
          </span>
          {delta && (
            <span data-testid={`macro-delta-${macroKey}`} className="text-[11px] font-semibold" style={{ color }}>
              {text}
            </span>
          )}
        </span>
      </div>
      <div className="relative h-2 overflow-hidden rounded-full bg-black/35">
        {hasGoal && (
          <div
            className="h-full rounded-full transition-[width] duration-700 ease-out"
            style={{
              width: `${pct}%`,
              boxShadow: `0 0 8px ${color}`,
              background: over
                ? `linear-gradient(90deg, ${color} ${goalPct}%, transparent ${goalPct}%), repeating-linear-gradient(135deg, ${color} 0 3px, rgba(0,0,0,0.35) 3px 5px)`
                : color,
            }}
          />
        )}
        {over && (
          <div
            data-testid={`macro-goal-marker-${macroKey}`}
            aria-hidden="true"
            className="absolute inset-y-0 w-[2px] -translate-x-1/2 bg-foreground"
            style={{ left: `${goalPct}%` }}
          />
        )}
      </div>
    </div>
  );
}

export default function TodayPanel({
  dailyGoal, todayTotal, caloriesEnabled, calorieStatus,
  enabledMacros, macroGoals, todayMacroTotals, macroStatuses, macroModes,
}: Props) {
  const { t } = useTranslation('dashboard');
  const deltaText = useDeltaText();
  const calorieDelta = caloriesEnabled ? goalDelta(todayTotal, dailyGoal, macroModes?.calories || 'limit') : null;
  if (!caloriesEnabled && enabledMacros.length === 0) {
    return (
      <p className="text-center text-sm text-muted-foreground py-6">
        {t('dashboard.noNutrientsTracked')} <a href="/settings">{t('dashboard.enableTrackingLink')}</a>
      </p>
    );
  }

  // Hero card: calorie budget ring on the left, macro bars on the right.
  return (
    <section className={cn(
      'surface flex items-center gap-5 p-5',
      enabledMacros.length === 0 && 'justify-center',
    )}>
      {caloriesEnabled && (
        <div className="flex shrink-0 flex-col items-center">
          <Ring
            macroKey="kcal"
            label={t('entries.caloriesLabel')}
            value={todayTotal}
            goal={dailyGoal}
            unit="kcal"
            status={calorieStatus}
            size={112}
          />
          {calorieDelta && (
            <span
              data-testid="calorie-delta"
              className="mt-1 text-[12px] font-semibold tabular-nums"
              style={{ color: ringColor(calorieStatus.statusClass, 'kcal') }}
            >
              {deltaText(calorieDelta)}
            </span>
          )}
        </div>
      )}
      {enabledMacros.length > 0 && (
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          {enabledMacros.map((key) => (
            <MacroBar
              key={key}
              macroKey={key}
              label={MACRO_LABELS[key as MacroKey]?.label || key}
              value={todayMacroTotals[key] || 0}
              goal={macroGoals[key] ?? null}
              mode={macroModes?.[key] || 'limit'}
              status={macroStatuses[key] || { statusClass: '', statusText: '' }}
            />
          ))}
        </div>
      )}
    </section>
  );
}
