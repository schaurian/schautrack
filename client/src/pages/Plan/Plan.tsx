import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { getPlan, applyBudget } from '@/api/plan';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import MetricsForm from './MetricsForm';
import GoalForm from './GoalForm';
import PlanChart from './PlanChart';

const BMI_CATEGORY_CLASSES: Record<string, string> = {
  underweight: 'bg-warning/10 border-warning/35 text-yellow-300',
  normal: 'bg-success/10 border-success/35 text-green-300',
  overweight: 'bg-warning/10 border-warning/35 text-yellow-300',
  obese: 'bg-destructive/10 border-destructive/35 text-red-300',
};

export default function Plan() {
  const { t } = useTranslation('dashboard');
  const { user, isLoading: authLoading } = useRequireAuth();
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [applying, setApplying] = useState(false);

  const BMI_CATEGORY_LABELS: Record<string, string> = {
    underweight: t('plan.bmiCategory.underweight'),
    normal: t('plan.bmiCategory.normal'),
    overweight: t('plan.bmiCategory.overweight'),
    obese: t('plan.bmiCategory.obese'),
  };

  const TREND_STATUS: Record<string, { label: string; classes: string }> = {
    ahead: { label: t('plan.trend.ahead'), classes: 'bg-success/10 border-success/35 text-green-300' },
    on_track: { label: t('plan.trend.onTrack'), classes: 'bg-success/10 border-success/35 text-green-300' },
    behind: { label: t('plan.trend.behind'), classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
    stalled: { label: t('plan.trend.stalled'), classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
    wrong_direction: { label: t('plan.trend.wrongDirection'), classes: 'bg-destructive/10 border-destructive/35 text-red-300' },
    insufficient_data: { label: t('plan.trend.insufficientData'), classes: 'bg-surface border-white/6 text-muted-foreground' },
  };

  const { data, isLoading } = useQuery({
    queryKey: ['plan'],
    queryFn: getPlan,
    enabled: !!user,
  });

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center py-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const weightUnit = user?.weightUnit || 'kg';

  const handleApplyBudget = async () => {
    setApplying(true);
    try {
      await applyBudget();
      queryClient.invalidateQueries({ queryKey: ['plan'] });
      queryClient.invalidateQueries({ queryKey: ['weight'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      addToast('success', t('plan.toastBudgetApplied'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('plan.toastBudgetApplyFailed'));
    }
    setApplying(false);
  };

  const bmiCategoryClass = data.bmiCategory ? BMI_CATEGORY_CLASSES[data.bmiCategory] : null;
  const trend = data.trend?.status ? TREND_STATUS[data.trend.status] : null;

  // Percent toward goal — works for both loss and gain goals since the sign
  // of (target - start) matches the sign of (current - start) when on track.
  let progressPct: number | null = null;
  if (data.goal && data.currentWeight != null) {
    const span = data.goal.target_weight - data.goal.start_weight;
    if (span !== 0) {
      progressPct = Math.min(Math.max(((data.currentWeight - data.goal.start_weight) / span) * 100, 0), 100);
    }
  }

  let budgetHelpText = '';
  if (!data.goal && !data.metrics.complete) budgetHelpText = t('plan.budgetHelp.needGoalAndMetrics');
  else if (!data.goal) budgetHelpText = t('plan.budgetHelp.needGoal');
  else if (!data.metrics.complete) budgetHelpText = t('plan.budgetHelp.needMetrics');
  else budgetHelpText = t('plan.budgetHelp.unavailable');

  return (
    <div className="flex flex-col gap-4">
      {/* Status header */}
      <div className="surface overflow-hidden">
        <div className="px-4 pt-4 pb-1">
          <h3 className="font-display text-[13px] font-bold tracking-wide text-[#c3ccdd]">{t('plan.status.title')}</h3>
        </div>
        <div className="p-4 grid gap-4 sm:grid-cols-3">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">{t('plan.status.currentWeightLabel')}</div>
            <div className="text-xl font-bold tabular-nums">
              {data.currentWeight != null ? data.currentWeight.toFixed(1) : '—'}
              <span className="text-sm text-muted-foreground font-normal ml-1">{weightUnit}</span>
            </div>
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">{t('plan.status.bmiLabel')}</div>
            {data.bmi != null ? (
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold tabular-nums">{data.bmi.toFixed(1)}</span>
                {data.bmiCategory && (
                  <span className={cn('rounded-full border px-2 py-0.5 text-xs font-semibold', bmiCategoryClass)}>
                    {BMI_CATEGORY_LABELS[data.bmiCategory] || data.bmiCategory}
                  </span>
                )}
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">{t('plan.status.addHeightWeight')}</div>
            )}
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">{t('plan.status.healthyRangeLabel')}</div>
            {data.healthyRange ? (
              <div className="text-xl font-bold tabular-nums">
                {data.healthyRange.minKg.toFixed(1)}&ndash;{data.healthyRange.maxKg.toFixed(1)}
                <span className="text-sm text-muted-foreground font-normal ml-1">{weightUnit}</span>
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">&mdash;</div>
            )}
          </div>
        </div>
      </div>

      <MetricsForm metrics={data.metrics} />

      <GoalForm
        goal={data.goal}
        computed={data.computed}
        warnings={data.warnings}
        weightUnit={weightUnit}
        metricsComplete={data.metrics.complete}
      />

      {/* Recommended budget */}
      <Card>
        <h3 className="text-sm font-semibold mb-3">{t('plan.recommendedBudget.title')}</h3>
        {data.computed ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-2xl font-bold tabular-nums text-primary">
                {Math.round(data.computed.budgetKcal)} <span className="text-sm text-muted-foreground font-normal">{t('plan.kcalPerDayUnit')}</span>
              </div>
              {data.currentCalorieGoal != null && (
                <div className="text-xs text-muted-foreground mt-1">{t('plan.recommendedBudget.currentGoalLabel', { value: data.currentCalorieGoal })}</div>
              )}
              {data.computed.budgetClamped && (
                <div className="text-xs text-yellow-400 mt-1">{t('plan.recommendedBudget.clampedNotice')}</div>
              )}
            </div>
            <Button onClick={handleApplyBudget} loading={applying}>{t('plan.recommendedBudget.applyButton')}</Button>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{budgetHelpText}</p>
        )}
      </Card>

      <PlanChart
        variant="full"
        series={data.series}
        planCurve={data.computed?.planCurve ?? []}
        targetWeight={data.goal?.target_weight ?? null}
        healthyRange={data.healthyRange}
        weightUnit={weightUnit}
      />

      {/* Progress */}
      {data.goal && (
        <Card>
          <h3 className="text-sm font-semibold mb-3">{t('plan.progress.title')}</h3>
          <div className="flex flex-wrap items-center gap-4">
            {progressPct != null && (
              <div className="flex-1 min-w-[160px]">
                <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                  <span>{t('plan.percentToGoal', { percent: progressPct.toFixed(0) })}</span>
                </div>
                <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                  <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${progressPct}%` }} />
                </div>
              </div>
            )}
            {trend && (
              <span className={cn('rounded-full border px-2.5 py-1 text-xs font-semibold', trend.classes)}>
                {trend.label}
              </span>
            )}
            {data.trend?.projectedDate && (
              <span className="text-xs text-muted-foreground">{t('plan.progress.projectedLabel', { date: data.trend.projectedDate })}</span>
            )}
          </div>
        </Card>
      )}

      {/* Disclaimer */}
      <p className="text-xs text-muted-foreground text-center">{data.disclaimer}</p>
    </div>
  );
}
