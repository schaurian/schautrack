import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { getPlan, applyBudget } from '@/api/plan';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import MetricsForm from './MetricsForm';
import GoalForm from './GoalForm';

const BMI_CATEGORY_LABELS: Record<string, string> = {
  underweight: 'Underweight',
  normal: 'Normal',
  overweight: 'Overweight',
  obese: 'Obese',
};

const BMI_CATEGORY_CLASSES: Record<string, string> = {
  underweight: 'bg-warning/10 border-warning/35 text-yellow-300',
  normal: 'bg-success/10 border-success/35 text-green-300',
  overweight: 'bg-warning/10 border-warning/35 text-yellow-300',
  obese: 'bg-destructive/10 border-destructive/35 text-red-300',
};

const TREND_STATUS: Record<string, { label: string; classes: string }> = {
  ahead: { label: 'Ahead of schedule', classes: 'bg-success/10 border-success/35 text-green-300' },
  on_track: { label: 'On track', classes: 'bg-success/10 border-success/35 text-green-300' },
  behind: { label: 'Behind schedule', classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
  stalled: { label: 'Stalled', classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
  wrong_direction: { label: 'Wrong direction', classes: 'bg-destructive/10 border-destructive/35 text-red-300' },
  insufficient_data: { label: 'Not enough data', classes: 'bg-surface border-white/6 text-muted-foreground' },
};

export default function Plan() {
  const { user, isLoading: authLoading } = useRequireAuth();
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [applying, setApplying] = useState(false);

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
      addToast('success', 'Calorie goal updated');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to apply budget');
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
  if (!data.goal && !data.metrics.complete) budgetHelpText = 'Set a goal and complete your details above to see a recommended budget.';
  else if (!data.goal) budgetHelpText = 'Set a goal above to see a recommended budget.';
  else if (!data.metrics.complete) budgetHelpText = 'Complete your details above to see a recommended budget.';

  return (
    <div className="flex flex-col gap-4">
      {/* Status header */}
      <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
        <div className="px-4 py-3 border-b-2 border-border">
          <h3 className="text-sm font-medium text-muted-foreground">Status</h3>
        </div>
        <div className="p-4 grid gap-4 sm:grid-cols-3">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">Current Weight</div>
            <div className="text-xl font-bold tabular-nums">
              {data.currentWeight != null ? data.currentWeight.toFixed(1) : '—'}
              <span className="text-sm text-muted-foreground font-normal ml-1">{weightUnit}</span>
            </div>
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">BMI</div>
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
              <div className="text-sm text-muted-foreground">Add height &amp; weight</div>
            )}
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">Healthy Range</div>
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
        <h3 className="text-sm font-semibold mb-3">Recommended Budget</h3>
        {data.computed ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-2xl font-bold tabular-nums text-primary">
                {Math.round(data.computed.budgetKcal)} <span className="text-sm text-muted-foreground font-normal">kcal/day</span>
              </div>
              {data.currentCalorieGoal != null && (
                <div className="text-xs text-muted-foreground mt-1">Current calorie goal: {data.currentCalorieGoal} kcal/day</div>
              )}
              {data.computed.budgetClamped && (
                <div className="text-xs text-yellow-400 mt-1">Clamped to a safe minimum</div>
              )}
            </div>
            <Button onClick={handleApplyBudget} loading={applying}>Apply as my calorie goal</Button>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{budgetHelpText}</p>
        )}
      </Card>

      {/* Chart placeholder */}
      <div className="rounded-xl border-2 border-dashed border-border bg-card/50 overflow-hidden p-8 flex items-center justify-center min-h-[200px]">
        {/* PlanChart mounted in Task 6 */}
        <span className="text-sm text-muted-foreground">Weight trend chart coming soon</span>
      </div>

      {/* Progress */}
      {data.goal && (
        <Card>
          <h3 className="text-sm font-semibold mb-3">Progress</h3>
          <div className="flex flex-wrap items-center gap-4">
            {progressPct != null && (
              <div className="flex-1 min-w-[160px]">
                <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                  <span>{progressPct.toFixed(0)}% to goal</span>
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
              <span className="text-xs text-muted-foreground">Projected: {data.trend.projectedDate}</span>
            )}
          </div>
        </Card>
      )}

      {/* Disclaimer */}
      <p className="text-xs text-muted-foreground text-center">{data.disclaimer}</p>
    </div>
  );
}
