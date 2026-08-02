import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { getPlan } from '@/api/plan';
import { cn } from '@/lib/utils';
import { SectionLabel } from '@/components/ui/SectionLabel';
import PlanChart from '../Plan/PlanChart';

interface Props {
  weightUnit: string;
}

export default function PlanCard({ weightUnit }: Props) {
  const { t } = useTranslation('dashboard');
  const { data } = useQuery({ queryKey: ['plan'], queryFn: getPlan });

  // Small local mapping — mirrors the status→label/color approach in Plan.tsx
  // (not exported there, so duplicated here rather than reaching across pages).
  const TREND_STATUS: Record<string, { label: string; classes: string }> = {
    ahead: { label: t('plan.card.trend.ahead'), classes: 'bg-success/10 border-success/35 text-green-300' },
    on_track: { label: t('plan.card.trend.onTrack'), classes: 'bg-success/10 border-success/35 text-green-300' },
    behind: { label: t('plan.card.trend.behind'), classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
    stalled: { label: t('plan.card.trend.stalled'), classes: 'bg-warning/10 border-warning/35 text-yellow-300' },
    wrong_direction: { label: t('plan.card.trend.wrongDirection'), classes: 'bg-destructive/10 border-destructive/35 text-red-300' },
    insufficient_data: { label: t('plan.card.trend.insufficientData'), classes: 'bg-surface border-white/6 text-muted-foreground' },
  };

  if (!data?.goal || data.goal.status !== 'active') return null;

  const { goal } = data;

  // Same formula as Plan.tsx: percent covered of (start -> target), clamped.
  let progressPct: number | null = null;
  if (data.currentWeight != null) {
    const span = goal.target_weight - goal.start_weight;
    if (span !== 0) {
      progressPct = Math.min(Math.max(((data.currentWeight - goal.start_weight) / span) * 100, 0), 100);
    }
  }

  const trend = data.trend?.status ? TREND_STATUS[data.trend.status] : null;

  return (
    <Link
      to="/plan"
      className="surface block p-4 no-underline text-foreground transition-[filter] hover:brightness-110"
    >
      <SectionLabel
        right={trend ? (
          <span className={cn('rounded-full border px-2 py-0.5 text-xs font-semibold', trend.classes)}>
            {trend.label}
          </span>
        ) : undefined}
      >
        {t('plan.card.title')}
      </SectionLabel>
      <div className="px-1 py-1 flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <div className="text-lg font-bold tabular-nums">
            {data.currentWeight != null ? data.currentWeight.toFixed(1) : '—'}
            <span className="text-sm text-muted-foreground font-normal"> {weightUnit}</span>
            <span className="text-muted-foreground font-normal mx-1.5">&rarr;</span>
            {goal.target_weight.toFixed(1)}
            <span className="text-sm text-muted-foreground font-normal"> {weightUnit}</span>
          </div>
        </div>

        {progressPct != null && (
          <div>
            <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
              <span>{t('plan.percentToGoal', { percent: progressPct.toFixed(0) })}</span>
            </div>
            <div className="h-2 rounded-full bg-white/10 overflow-hidden">
              <div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{ width: `${progressPct}%` }} />
            </div>
          </div>
        )}

        <PlanChart
          variant="spark"
          series={data.series}
          planCurve={[]}
          targetWeight={goal.target_weight}
          healthyRange={data.healthyRange}
          weightUnit={weightUnit}
        />
      </div>
    </Link>
  );
}
