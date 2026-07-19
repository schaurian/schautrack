import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { PlanMetrics } from '@/types';
import { updateMetrics } from '@/api/plan';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';
const selectClass = inputClass;

const ACTIVITY_LABELS: Record<string, string> = {
  sedentary: 'Sedentary (little or no exercise)',
  light: 'Light (1-3 days/week)',
  moderate: 'Moderate (3-5 days/week)',
  active: 'Active (6-7 days/week)',
  very_active: 'Very Active (physical job or 2x/day)',
};

interface Props {
  metrics: PlanMetrics;
}

export default function MetricsForm({ metrics }: Props) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const [open, setOpen] = useState(!metrics.complete);
  const [height, setHeight] = useState(metrics.heightCm != null ? String(metrics.heightCm) : '');
  const [birthYear, setBirthYear] = useState(metrics.birthYear != null ? String(metrics.birthYear) : '');
  const [sex, setSex] = useState(metrics.sex || '');
  const [activityLevel, setActivityLevel] = useState(metrics.activityLevel || '');
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateMetrics({
        height_cm: height ? Number(height) : null,
        birth_year: birthYear ? Number(birthYear) : null,
        sex: (sex || null) as 'male' | 'female' | 'other' | null,
        activity_level: activityLevel || null,
      });
      queryClient.invalidateQueries({ queryKey: ['plan'] });
      addToast('success', 'Details saved');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save details');
    }
    setSaving(false);
  };

  return (
    <Card>
      <button type="button" className="flex w-full items-center justify-between cursor-pointer" onClick={() => setOpen(!open)}>
        <h3 className="text-sm font-semibold">Your Details</h3>
        <span className="text-xs text-muted-foreground">
          {metrics.complete ? (open ? 'Hide' : 'Edit') : 'Complete your profile'}
        </span>
      </button>
      {open && (
        <div className="mt-4 flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Height (cm)</label>
              <input className={inputClass} type="number" min="0" max="300" value={height} onChange={(e) => setHeight(e.target.value)} placeholder="e.g. 175" />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Birth Year</label>
              <input className={inputClass} type="number" min="1900" max="2100" value={birthYear} onChange={(e) => setBirthYear(e.target.value)} placeholder="e.g. 1990" />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Sex</label>
              <select className={selectClass} value={sex} onChange={(e) => setSex(e.target.value)}>
                <option value="">Select…</option>
                <option value="male">Male</option>
                <option value="female">Female</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Activity Level</label>
              <select className={selectClass} value={activityLevel} onChange={(e) => setActivityLevel(e.target.value)}>
                <option value="">Select…</option>
                {Object.entries(ACTIVITY_LABELS).map(([key, label]) => (
                  <option key={key} value={key}>{label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={handleSave} loading={saving} size="sm">Save Details</Button>
          </div>
        </div>
      )}
    </Card>
  );
}
