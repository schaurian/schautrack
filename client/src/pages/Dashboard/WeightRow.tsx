import { useState, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { WeightEntry } from '@/types';
import { upsertWeight, deleteWeight } from '@/api/weight';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  weightEntry: WeightEntry | null;
  lastWeightEntry: WeightEntry | null;
  weightUnit: string;
  canEdit: boolean;
  selectedDate: string;
}

export default function WeightRow({ weightEntry, lastWeightEntry, weightUnit, canEdit, selectedDate }: Props) {
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
      addToast('success', 'Weight tracked');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save weight');
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
      addToast('error', err instanceof Error ? err.message : 'Failed to delete weight');
    }
    setLoading(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSave();
    }
  };

  const handleBlur = () => {
    const raw = inputRef.current?.value.trim() || '';
    const num = parseFloat(raw);
    if (num && num > 0 && num !== entry?.weight) {
      handleSave();
    }
  };

  if (!entry && !canEdit) return null;

  const colorClass = isToday ? 'text-green-400' : 'text-muted-foreground';

  return (
    <div className="border-t-2 border-border px-4 py-3">
      <div className="flex items-center gap-3">
        <span className="text-sm text-muted-foreground">Weight</span>
        {canEdit ? (
          <div className="relative">
            <input
              ref={inputRef}
              className={`w-24 bg-transparent border-0 p-0 text-lg font-semibold tabular-nums outline-none ${colorClass}`}
              type="text"
              inputMode="decimal"
              defaultValue={displayValue}
              key={`${selectedDate}-${entry?.id}-${entry?.weight}`}
              onKeyDown={handleKeyDown}
              onBlur={handleBlur}
              placeholder="0.0"
              disabled={loading}
              aria-label={`Weight in ${weightUnit}`}
            />
          </div>
        ) : (
          <span className={`text-lg font-semibold tabular-nums ${colorClass}`}>
            {entry ? Number(entry.weight).toFixed(1) : '—'}
          </span>
        )}
        <span className="text-sm text-muted-foreground">{weightUnit}</span>
        {!isToday && entry?.entry_date && (
          <span className="text-xs text-muted-foreground/60">{entry.entry_date}</span>
        )}
        {canEdit && weightEntry && (
          <button
            type="button"
            className="bg-transparent border-0 p-0 ml-auto text-muted-foreground/60 hover:text-destructive cursor-pointer transition-colors text-lg leading-none"
            onClick={handleDelete}
            title="Delete"
          >
            &times;
          </button>
        )}
      </div>
    </div>
  );
}
