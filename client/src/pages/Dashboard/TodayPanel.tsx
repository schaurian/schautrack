import { useTranslation } from 'react-i18next';
import type { MacroStatus } from '@/types';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';
import { ringProgress, ringColor } from '@/lib/ring';
import { Ring } from '@/components/ui/Ring';
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
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

// One glowing bar per macro — easier to compare against each other than
// mini-rings; the big calorie ring keeps the single budget number focal.
function MacroBar({ macroKey, label, value, goal, status }: {
  macroKey: string;
  label: string;
  value: number;
  goal: number | null;
  status: MacroStatus;
}) {
  const hasGoal = goal != null && goal > 0;
  const pct = hasGoal ? ringProgress(value, goal) : 0;
  const color = ringColor(status.statusClass, macroKey);
  return (
    <div
      role="img"
      aria-label={`${label}: ${value}${hasGoal ? ` / ${goal}` : ''} g`}
      title={status.statusText || undefined}
    >
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[12px] leading-none">
        <span className={cn('font-display font-bold', LABEL_COLORS[macroKey] || 'text-primary')}>{label}</span>
        <span className="font-bold tabular-nums text-[#c3ccdd]">
          {value}
          <span className="font-normal text-muted-foreground">{hasGoal ? `/${goal}g` : 'g'}</span>
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-black/35">
        {hasGoal && (
          <div
            className="h-full rounded-full transition-[width] duration-700 ease-out"
            style={{ width: `${pct}%`, background: color, boxShadow: `0 0 8px ${color}` }}
          />
        )}
      </div>
    </div>
  );
}

export default function TodayPanel({
  dailyGoal, todayTotal, caloriesEnabled, calorieStatus,
  enabledMacros, macroGoals, todayMacroTotals, macroStatuses,
}: Props) {
  const { t } = useTranslation('dashboard');
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
        <Ring
          macroKey="kcal"
          label={t('entries.caloriesLabel')}
          value={todayTotal}
          goal={dailyGoal}
          unit="kcal"
          status={calorieStatus}
          size={112}
        />
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
              status={macroStatuses[key] || { statusClass: '', statusText: '' }}
            />
          ))}
        </div>
      )}
    </section>
  );
}
