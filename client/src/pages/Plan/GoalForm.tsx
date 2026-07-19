import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { WeightGoal, PlanComputed, PlanWarning } from '@/types';
import { upsertGoal } from '@/api/plan';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
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
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [targetWeight, setTargetWeight] = useState(goal ? String(goal.target_weight) : '');
  const [paceMode, setPaceMode] = useState<'rate' | 'date'>(goal?.pace_mode || 'rate');
  const [rate, setRate] = useState(goal?.rate_kg_per_week != null ? String(goal.rate_kg_per_week) : '');
  const [targetDate, setTargetDate] = useState(goal?.target_date || '');
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    const tw = parseFloat(targetWeight);
    if (!tw || tw <= 0) {
      addToast('error', 'Enter a valid target weight');
      return;
    }
    if (paceMode === 'rate' && !rate) {
      addToast('error', 'Enter a weekly rate');
      return;
    }
    if (paceMode === 'date' && !targetDate) {
      addToast('error', 'Choose a target date');
      return;
    }
    setSaving(true);
    try {
      await upsertGoal({
        target_weight: tw,
        pace_mode: paceMode,
        ...(paceMode === 'rate' ? { rate_kg_per_week: parseFloat(rate) } : { target_date: targetDate }),
      });
      queryClient.invalidateQueries({ queryKey: ['plan'] });
      addToast('success', 'Goal saved');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save goal');
    }
    setSaving(false);
  };

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">Goal Setup</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5 max-w-xs">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Weight</label>
          <span className="relative flex items-center">
            <input className={cn(inputClass, 'pr-10')} type="number" step="0.1" min="0" value={targetWeight} onChange={(e) => setTargetWeight(e.target.value)} placeholder="0.0" />
            <span className="absolute right-2.5 text-[10px] tracking-wide text-muted-foreground opacity-60 pointer-events-none">{weightUnit}</span>
          </span>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Pace</label>
          <div className="flex gap-2">
            <Button type="button" size="sm" variant={paceMode === 'rate' ? 'default' : 'ghost'} onClick={() => setPaceMode('rate')}>
              By rate
            </Button>
            <Button type="button" size="sm" variant={paceMode === 'date' ? 'default' : 'ghost'} onClick={() => setPaceMode('date')}>
              By date
            </Button>
          </div>
        </div>

        {paceMode === 'rate' ? (
          <div className="flex flex-col gap-1.5 max-w-xs">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{weightUnit}/week</label>
            <input className={inputClass} type="number" step="0.05" value={rate} onChange={(e) => setRate(e.target.value)} placeholder="e.g. 0.5" />
          </div>
        ) : (
          <div className="flex flex-col gap-1.5 max-w-xs">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Date</label>
            <input className={inputClass} type="date" value={targetDate} onChange={(e) => setTargetDate(e.target.value)} />
          </div>
        )}

        {!metricsComplete && (
          <p className="text-xs text-muted-foreground">Complete your details above to compute a calorie budget for this goal.</p>
        )}

        {warnings.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {warnings.map((w) => (
              <p key={w.code} className="rounded-md border border-warning/30 bg-warning/10 px-2.5 py-1.5 text-xs text-yellow-300">
                {w.message}
              </p>
            ))}
          </div>
        )}

        {computed && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 rounded-lg border border-border bg-muted/30 px-3 py-2.5 text-sm">
            <div>
              <span className="text-muted-foreground">Budget: </span>
              <span className="font-semibold">{Math.round(computed.budgetKcal)} kcal/day</span>
            </div>
            {computed.etaDate && (
              <div>
                <span className="text-muted-foreground">ETA: </span>
                <span className="font-semibold">{computed.etaDate}</span>
              </div>
            )}
            <div>
              <span className="text-muted-foreground">~</span>
              <span className="font-semibold">{computed.etaWeeks}</span>
              <span className="text-muted-foreground"> weeks</span>
            </div>
          </div>
        )}

        <div className="flex justify-end">
          <Button onClick={handleSave} loading={saving} size="sm">Save Goal</Button>
        </div>
      </div>
    </Card>
  );
}
