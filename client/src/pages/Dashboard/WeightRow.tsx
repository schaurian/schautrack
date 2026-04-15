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
      inputRef.current?.blur();
    }
  };

  const handleBlur = () => {
    const raw = inputRef.current?.value.trim() || '';
    const num = parseFloat(raw);
    if (num && num > 0 && (num !== entry?.weight || !isToday)) {
      handleSave();
    }
  };

  if (!entry && !canEdit) return null;

  const colorClass = isToday ? 'text-green-400' : 'text-muted-foreground';

  const daysAgo = !isToday && entry?.entry_date
    ? Math.round((new Date(selectedDate).getTime() - new Date(entry.entry_date).getTime()) / 86400000)
    : 0;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Weight</h3>
        {!isToday && entry?.entry_date && (
          <span className="text-sm text-muted-foreground">
            {entry.entry_date} &middot; {daysAgo === 1 ? '1 day ago' : `${daysAgo} days ago`}
          </span>
        )}
      </div>
      <div className="flex items-center gap-3 p-4">
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
              aria-label={`Weight in ${weightUnit}`}
            />
            <span className="absolute right-3 text-[10px] tracking-wide text-muted-foreground opacity-60 pointer-events-none">{weightUnit}</span>
          </span>
        ) : (
          <span className={`text-lg font-semibold tabular-nums ${colorClass}`}>
            {entry ? Number(entry.weight).toFixed(1) : '—'}
            <span className="text-sm text-muted-foreground font-normal ml-1">{weightUnit}</span>
          </span>
        )}
        {canEdit && (
          <button
            type="button"
            className={`ml-auto rounded-md px-4 py-2 text-sm font-semibold border transition-colors ${
              weightEntry
                ? 'text-destructive border-destructive/30 bg-destructive/10 hover:bg-destructive/20 cursor-pointer'
                : 'text-muted-foreground/40 border-border bg-muted/30 cursor-default'
            }`}
            onClick={handleDelete}
            disabled={!weightEntry}
            title="Delete weight entry"
          >
            Delete
          </button>
        )}
      </div>
    </div>
  );
}
