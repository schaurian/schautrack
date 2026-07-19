import { useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import type { WeightEntry } from '@/types';
import { upsertWeight, deleteWeight } from '@/api/weight';
import { useToastStore } from '@/stores/toastStore';
import { SectionLabel } from '@/components/ui/SectionLabel';

interface Props {
  weightEntry: WeightEntry | null;
  lastWeightEntry: WeightEntry | null;
  weightUnit: string;
  canEdit: boolean;
  selectedDate: string;
}

export default function WeightRow({ weightEntry, lastWeightEntry, weightUnit, canEdit, selectedDate }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);
  const inputRef = useRef<HTMLInputElement>(null);

  const entry = weightEntry || lastWeightEntry;
  const isToday = !!weightEntry;
  const displayValue = entry ? String(Number(entry.weight)) : '';

  const handleSave = async () => {
    const raw = inputRef.current?.value.trim() || '';
    const num = parseFloat(raw);
    if (!num || num <= 0) return;
    setLoading(true);
    try {
      await upsertWeight({ date: selectedDate, weight: num });
      queryClient.invalidateQueries({ queryKey: ['weight'] });
      addToast('success', t('weight.toastTracked'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('weight.toastSaveFailed'));
    }
    setLoading(false);
  };

  const handleDelete = async () => {
    if (!weightEntry) return;
    setLoading(true);
    try {
      await deleteWeight(weightEntry.id);
      queryClient.invalidateQueries({ queryKey: ['weight'] });
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('weight.toastDeleteFailed'));
    }
    setLoading(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      inputRef.current?.blur();
    }
  };

  const handleBlur = () => {
    const raw = inputRef.current?.value.trim() || '';
    // Only save if the user actually changed the rendered value. Without
    // this, focus+blur on a date with no entry would silently write the
    // pre-filled previous weight to that date.
    if (raw === displayValue) return;
    const num = parseFloat(raw);
    if (num && num > 0) {
      handleSave();
    }
  };

  if (!entry && !canEdit) return null;

  const colorClass = isToday ? 'text-green-400' : 'text-muted-foreground';

  const daysAgo = !isToday && entry?.entry_date
    ? Math.round((new Date(selectedDate).getTime() - new Date(entry.entry_date).getTime()) / 86400000)
    : 0;

  return (
    <section className="surface p-4">
      <SectionLabel
        right={!isToday && entry?.entry_date ? (
          <span className="text-xs text-muted-foreground">
            {entry.entry_date} &middot; {t('weight.daysAgo', { count: daysAgo })}
          </span>
        ) : undefined}
      >
        {t('weight.sectionTitle')}
      </SectionLabel>
      <div className="flex items-center gap-3 px-1 py-1">
        {canEdit ? (
          <span className="relative flex items-center flex-1">
            <input
              ref={inputRef}
              className={`w-full rounded-md border bg-muted/50 px-3 py-2 pr-10 text-sm outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring ${isToday ? 'border-green-500/40 text-green-400' : 'border-input text-foreground'}`}
              type="text"
              inputMode="decimal"
              defaultValue={displayValue}
              key={`${selectedDate}-${entry?.id}-${entry?.weight}`}
              onKeyDown={handleKeyDown}
              onBlur={handleBlur}
              placeholder="0.0"
              disabled={loading}
              aria-label={t('weight.weightInUnitAriaLabel', { unit: weightUnit })}
            />
            <span className="absolute right-3 text-[10px] tracking-wide text-muted-foreground opacity-60 pointer-events-none">{weightUnit}</span>
          </span>
        ) : (
          <span className={`text-lg font-semibold tabular-nums ${colorClass}`}>
            {entry ? Number(entry.weight).toFixed(1) : '—'}
            <span className="text-sm text-muted-foreground font-normal ml-1">{weightUnit}</span>
          </span>
        )}
        {canEdit && weightEntry && (
          <button
            type="button"
            className="ml-auto cursor-pointer rounded-md border border-destructive/25 bg-transparent px-3 py-2 text-sm font-semibold text-destructive/90 transition-colors hover:bg-destructive/10"
            onClick={handleDelete}
            title={t('weight.deleteEntryTitle')}
          >
            {t('weight.deleteButton')}
          </button>
        )}
      </div>
    </section>
  );
}
