import { useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import type { WeightEntry } from '@/types';
import { upsertWeight, deleteWeight } from '@/api/weight';
import { MAX_BODY_FAT_PCT, parseBodyFatInput } from '@/lib/bodyFat';
import { useToastStore } from '@/stores/toastStore';
import { SectionLabel } from '@/components/ui/SectionLabel';

interface Props {
  weightEntry: WeightEntry | null;
  lastWeightEntry: WeightEntry | null;
  weightUnit: string;
  canEdit: boolean;
  selectedDate: string;
  bodyFatEnabled?: boolean;
}

export default function WeightRow({ weightEntry, lastWeightEntry, weightUnit, canEdit, selectedDate, bodyFatEnabled = false }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);
  const inputRef = useRef<HTMLInputElement>(null);
  const bodyFatRef = useRef<HTMLInputElement>(null);

  const entry = weightEntry || lastWeightEntry;
  const isToday = !!weightEntry;
  const displayValue = entry ? String(Number(entry.weight)) : '';
  // Only the selected date's own reading, never the last one: a stale body fat
  // is not a useful pre-fill, and showing one would invite saving it to today.
  const bodyFatValue = weightEntry?.body_fat != null ? String(Number(weightEntry.body_fat)) : '';

  const handleSave = async () => {
    const raw = inputRef.current?.value.trim() || '';
    const num = parseFloat(raw);
    if (!num || num <= 0) return;
    setLoading(true);
    try {
      // No body_fat key: this path only ever means "save the weight", and the
      // server preserves whatever reading the date already has.
      await upsertWeight({ date: selectedDate, weight: num });
      queryClient.invalidateQueries({ queryKey: ['weight'] });
      addToast('success', t('weight.toastTracked'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('weight.toastSaveFailed'));
    }
    setLoading(false);
  };

  const handleSaveBodyFat = async () => {
    // The field is disabled until the date has a weight entry, so there is
    // always a stored weight for the server to keep.
    if (!weightEntry) return;
    const parsed = parseBodyFatInput(bodyFatRef.current?.value ?? '');
    if (!parsed.ok) {
      // Rejected here rather than round-tripping only to come back as a
      // generic server error — the bound is the same on both sides.
      addToast('error', t('weight.toastBodyFatInvalid', { max: MAX_BODY_FAT_PCT }));
      return;
    }
    setLoading(true);
    try {
      // No weight key: this path only ever means "save the body fat", and the
      // weight it would otherwise send is a cached value the user did not just
      // measure — re-asserting it reverts a newer weight logged elsewhere.
      await upsertWeight({ date: selectedDate, body_fat: parsed.value });
      queryClient.invalidateQueries({ queryKey: ['weight'] });
      addToast('success', parsed.value === null ? t('weight.toastBodyFatCleared') : t('weight.toastBodyFatTracked'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('weight.toastBodyFatSaveFailed'));
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
      (e.target as HTMLInputElement).blur();
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

  const handleBodyFatBlur = () => {
    const raw = bodyFatRef.current?.value.trim() || '';
    if (raw === bodyFatValue) return;
    handleSaveBodyFat();
  };

  if (!entry && !canEdit) return null;

  const colorClass = isToday ? 'text-green-400' : 'text-muted-foreground';

  const daysAgo = !isToday && entry?.entry_date
    ? Math.round((new Date(selectedDate).getTime() - new Date(entry.entry_date).getTime()) / 86400000)
    : 0;

  // On your own row the preference decides. On a linked account's row it does
  // not: they shared their weight and the reading rides along with it, so
  // hiding it because *you* don't track body fat would drop shared data for an
  // unrelated reason.
  const showBodyFat = canEdit ? bodyFatEnabled : weightEntry?.body_fat != null;

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
        {showBodyFat && (canEdit ? (
          <span className="relative flex items-center w-24 shrink-0">
            <input
              ref={bodyFatRef}
              className={`w-full rounded-md border bg-muted/50 px-3 py-2 pr-7 text-sm outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring disabled:opacity-50 ${weightEntry?.body_fat != null ? 'border-green-500/40 text-green-400' : 'border-input text-foreground'}`}
              type="text"
              inputMode="decimal"
              defaultValue={bodyFatValue}
              key={`bf-${selectedDate}-${weightEntry?.id}-${weightEntry?.body_fat}`}
              onKeyDown={handleKeyDown}
              onBlur={handleBodyFatBlur}
              placeholder={t('weight.bodyFatPlaceholder')}
              // A body-fat reading belongs to a weight, so there is nothing to
              // attach it to until the day has one.
              disabled={loading || !weightEntry}
              aria-label={t('weight.bodyFatAriaLabel')}
            />
            <span className="absolute right-2.5 text-[10px] tracking-wide text-muted-foreground opacity-60 pointer-events-none">%</span>
          </span>
        ) : (
          <span className="text-lg font-semibold tabular-nums text-muted-foreground">
            {/* showBodyFat already proved this branch has a reading; reading it
                through `?.` would quietly render "NaN" if that ever stopped
                holding, so take the value directly and let it fail loudly. */}
            {Number(bodyFatValue).toFixed(1)}
            <span className="text-sm font-normal ml-1">%</span>
          </span>
        ))}
        {canEdit && weightEntry && (
          <button
            type="button"
            className="ml-auto cursor-pointer rounded-md border border-destructive/25 bg-transparent px-3 py-2 text-sm font-semibold text-destructive/90 transition-colors hover:bg-destructive/10"
            onClick={handleDelete}
            title={t('weight.deleteEntryTitle')}
            // Visible text wins over title in the accessible name, so without
            // this a screen reader announces a context-free "Delete".
            aria-label={t('weight.deleteEntryTitle')}
          >
            {t('weight.deleteButton')}
          </button>
        )}
      </div>
      {showBodyFat && canEdit && (
        <p className="px-1 pt-1.5 text-xs text-muted-foreground">
          {weightEntry ? t('weight.bodyFatHint') : t('weight.bodyFatNeedsWeight')}
        </p>
      )}
    </section>
  );
}
