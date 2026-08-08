import { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import type { WeightGoal, PlanComputed, PlanWarning } from '@/types';
import { upsertGoal } from '@/api/plan';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { useAutosave } from '@/hooks/useAutosave';
import { cn } from '@/lib/utils';

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  goal: WeightGoal | null;
  computed: PlanComputed | null;
  warnings: PlanWarning[];
  weightUnit: string;
  metricsComplete: boolean;
}

export default function GoalForm({ goal, computed, warnings, weightUnit, metricsComplete }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const [targetWeight, setTargetWeight] = useState(goal ? String(goal.target_weight) : '');
  const [paceMode, setPaceMode] = useState<'rate' | 'date'>(goal?.pace_mode || 'rate');
  const [rate, setRate] = useState(goal?.rate_per_week != null ? String(goal.rate_per_week) : '');
  const [targetDate, setTargetDate] = useState(goal?.target_date || '');

  // Autosaves like every other form. A goal is only writable once it has a
  // target weight and a pace, so an incomplete form simply doesn't save —
  // quieter than toasting a validation error on every keystroke.
  const complete = Number(targetWeight) > 0 && (paceMode === 'rate' ? !!rate : !!targetDate);
  const data = useMemo(
    () => ({ targetWeight, paceMode, rate, targetDate }),
    [targetWeight, paceMode, rate, targetDate],
  );

  const saveFn = useCallback(async (d: typeof data) => {
    await upsertGoal({
      target_weight: parseFloat(d.targetWeight),
      pace_mode: d.paceMode,
      ...(d.paceMode === 'rate'
        ? { rate_per_week: parseFloat(d.rate) }
        : { target_date: d.targetDate }),
    });
    queryClient.invalidateQueries({ queryKey: ['plan'] });
  }, [queryClient]);

  useAutosave(data, saveFn, { delay: 1000, enabled: complete });

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">{t('plan.goalForm.title')}</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5 max-w-xs">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.goalForm.targetWeightLabel')}</label>
          <span className="relative flex items-center">
            <input className={cn(inputClass, 'pr-10')} type="number" step="0.1" min="0" value={targetWeight} onChange={(e) => setTargetWeight(e.target.value)} placeholder="0.0" />
            <span className="absolute right-2.5 text-[10px] tracking-wide text-muted-foreground opacity-60 pointer-events-none">{weightUnit}</span>
          </span>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.goalForm.paceLabel')}</label>
          <div className="flex gap-2">
            <Button type="button" size="sm" variant={paceMode === 'rate' ? 'default' : 'ghost'} onClick={() => setPaceMode('rate')}>
              {t('plan.goalForm.byRateButton')}
            </Button>
            <Button type="button" size="sm" variant={paceMode === 'date' ? 'default' : 'ghost'} onClick={() => setPaceMode('date')}>
              {t('plan.goalForm.byDateButton')}
            </Button>
          </div>
        </div>

        {paceMode === 'rate' ? (
          <div className="flex flex-col gap-1.5 max-w-xs">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.goalForm.rateUnitLabel', { unit: weightUnit })}</label>
            <input className={inputClass} type="number" step="0.05" min="0" value={rate} onChange={(e) => setRate(e.target.value)} placeholder={t('plan.goalForm.ratePlaceholder')} />
          </div>
        ) : (
          <div className="flex flex-col gap-1.5 max-w-xs">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.goalForm.targetDateLabel')}</label>
            <input className={inputClass} type="date" value={targetDate} onChange={(e) => setTargetDate(e.target.value)} />
          </div>
        )}

        {!metricsComplete && (
          <p className="text-xs text-muted-foreground">{t('plan.goalForm.completeDetailsHint')}</p>
        )}

        {warnings.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {warnings.map((w, i) => (
              <p key={`${w.code}-${i}`} className="rounded-md border border-warning/30 bg-warning/10 px-2.5 py-1.5 text-xs text-yellow-300">
                {w.message}
              </p>
            ))}
          </div>
        )}

        {computed && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 rounded-lg border border-border bg-muted/30 px-3 py-2.5 text-sm">
            <div>
              <span className="text-muted-foreground">{t('plan.goalForm.budgetLabel')}</span>
              <span className="font-semibold">{Math.round(computed.budgetKcal)} {t('plan.kcalPerDayUnit')}</span>
            </div>
            {computed.etaDate && (
              <div>
                <span className="text-muted-foreground">{t('plan.goalForm.etaLabel')}</span>
                <span className="font-semibold">{computed.etaDate}</span>
              </div>
            )}
            <div>
              <span className="text-muted-foreground">~</span>
              <span className="font-semibold">{Math.round(computed.etaWeeks)}</span>
              <span className="text-muted-foreground">{t('plan.goalForm.weeksLabel', { count: Math.round(computed.etaWeeks) })}</span>
            </div>
          </div>
        )}

      </div>
    </Card>
  );
}
