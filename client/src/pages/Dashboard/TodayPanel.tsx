import { useTranslation } from 'react-i18next';
import type { MacroStatus } from '@/types';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';
import { Ring } from '@/components/ui/Ring';

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

  return (
    <section className="flex flex-wrap items-start justify-center gap-x-4 gap-y-4 py-2 sm:gap-x-6">
      {caloriesEnabled && (
        <Ring
          macroKey="kcal"
          label={t('entries.caloriesLabel')}
          value={todayTotal}
          goal={dailyGoal}
          unit="kcal"
          status={calorieStatus}
        />
      )}
      {enabledMacros.map((key) => (
        <Ring
          key={key}
          macroKey={key}
          label={MACRO_LABELS[key as MacroKey]?.label || key}
          value={todayMacroTotals[key] || 0}
          goal={macroGoals[key] ?? null}
          unit="g"
          status={macroStatuses[key] || { statusClass: '', statusText: '' }}
        />
      ))}
    </section>
  );
}
