import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import type { PlanMetrics } from '@/types';
import { updateMetrics, clearMetrics } from '@/api/plan';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';
const selectClass = inputClass;

const ACTIVITY_LEVELS: { value: string; labelKey: string }[] = [
  { value: 'sedentary', labelKey: 'sedentary' },
  { value: 'light', labelKey: 'light' },
  { value: 'moderate', labelKey: 'moderate' },
  { value: 'active', labelKey: 'active' },
  { value: 'very_active', labelKey: 'veryActive' },
];

interface Props {
  metrics: PlanMetrics;
}

export default function MetricsForm({ metrics }: Props) {
  const { t } = useTranslation('dashboard');
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
      addToast('success', t('plan.metricsForm.toastSaved'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('plan.metricsForm.toastSaveFailed'));
    }
    setSaving(false);
  };

  // Consent-withdrawal path: saves preserve omitted fields, so this dedicated
  // action is the only way to actually erase body metrics short of account
  // deletion (promised in the privacy policy — keep it working).
  const handleClear = async () => {
    setSaving(true);
    try {
      await clearMetrics();
      setHeight('');
      setBirthYear('');
      setSex('');
      setActivityLevel('');
      queryClient.invalidateQueries({ queryKey: ['plan'] });
      addToast('success', t('plan.metricsForm.toastCleared'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('plan.metricsForm.toastClearFailed'));
    }
    setSaving(false);
  };

  return (
    <Card>
      <button type="button" className="flex w-full items-center justify-between cursor-pointer" onClick={() => setOpen(!open)}>
        <h3 className="text-sm font-semibold">{t('plan.metricsForm.title')}</h3>
        <span className="text-xs text-muted-foreground">
          {metrics.complete ? (open ? t('plan.metricsForm.hideLabel') : t('plan.metricsForm.editLabel')) : t('plan.metricsForm.completeProfileLabel')}
        </span>
      </button>
      {open && (
        <div className="mt-4 flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.metricsForm.heightLabel')}</label>
              <input className={inputClass} type="number" min="0" max="300" value={height} onChange={(e) => setHeight(e.target.value)} placeholder={t('plan.metricsForm.heightPlaceholder')} />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.metricsForm.birthYearLabel')}</label>
              <input className={inputClass} type="number" min="1900" max={new Date().getFullYear() - 10} value={birthYear} onChange={(e) => setBirthYear(e.target.value)} placeholder={t('plan.metricsForm.birthYearPlaceholder')} />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.metricsForm.sexLabel')}</label>
              <select className={selectClass} value={sex} onChange={(e) => setSex(e.target.value)}>
                <option value="">{t('plan.metricsForm.selectPlaceholder')}</option>
                <option value="male">{t('plan.metricsForm.sexMale')}</option>
                <option value="female">{t('plan.metricsForm.sexFemale')}</option>
                <option value="other">{t('plan.metricsForm.sexOther')}</option>
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('plan.metricsForm.activityLevelLabel')}</label>
              <select className={selectClass} value={activityLevel} onChange={(e) => setActivityLevel(e.target.value)}>
                <option value="">{t('plan.metricsForm.selectPlaceholder')}</option>
                {ACTIVITY_LEVELS.map(({ value, labelKey }) => (
                  <option key={value} value={value}>{t(`plan.metricsForm.activity.${labelKey}`)}</option>
                ))}
              </select>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            {t('plan.metricsForm.consentNotice')}
          </p>
          <div className="flex justify-between">
            <Button onClick={handleClear} loading={saving} size="sm" variant="ghost" disabled={metrics.heightCm == null && metrics.birthYear == null && metrics.sex == null && metrics.activityLevel == null}>{t('plan.metricsForm.clearButton')}</Button>
            <Button onClick={handleSave} loading={saving} size="sm">{t('plan.metricsForm.saveButton')}</Button>
          </div>
        </div>
      )}
    </Card>
  );
}
