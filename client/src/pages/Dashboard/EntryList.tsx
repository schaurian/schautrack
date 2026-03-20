import { useState } from 'react';
import type { Entry } from '@/types';
import { updateEntry, deleteEntry } from '@/api/entries';
import { useQueryClient } from '@tanstack/react-query';
import { MACRO_LABELS } from '@/lib/macros';
import { cn } from '@/lib/utils';
import { useToastStore } from '@/stores/toastStore';

const HEADER_COLORS: Record<string, string> = {
  protein: 'text-macro-protein',
  carbs: 'text-macro-carbs',
  fat: 'text-macro-fat',
  fiber: 'text-macro-fiber',
  sugar: 'text-macro-sugar',
};

interface Props {
  entries: Entry[];
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
}

export default function EntryList({ entries, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories }: Props) {
  const queryClient = useQueryClient();

  if (entries.length === 0) {
    return <p className="text-center text-sm text-muted-foreground py-4">No entries for this day.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[320px]">
      <div className="flex gap-1.5 sm:gap-2 px-3 py-2 bg-muted/30 border-b-2 border-border text-xs uppercase tracking-wider text-muted-foreground font-medium">
        <span className="w-10 sm:w-16 shrink-0">Time</span>
        {caloriesEnabled && <span className="w-10 sm:w-16 shrink-0 text-macro-kcal">Cal</span>}
        {enabledMacros.map((key) => (
          <span key={key} className={cn('w-8 sm:w-14 shrink-0', HEADER_COLORS[key] || '')}>
            {MACRO_LABELS[key as keyof typeof MACRO_LABELS]?.short || key}
          </span>
        ))}
        <span className="flex-1 min-w-[48px]">Name</span>
        {canEdit && <span className="w-6 shrink-0" />}
      </div>

      {entries.map((entry) => (
        <EntryRow
          key={entry.id}
          entry={entry}
          canEdit={canEdit}
          enabledMacros={enabledMacros}
          caloriesEnabled={caloriesEnabled}
          autoCalcCalories={autoCalcCalories}
          onUpdate={() => {
            queryClient.invalidateQueries({ queryKey: ['dashboard'] });
            queryClient.invalidateQueries({ queryKey: ['day-entries'] });
          }}
        />
      ))}
      </div>
    </div>
  );
}

function EntryRow({ entry, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories, onUpdate }: {
  entry: Entry;
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  onUpdate: () => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const addToast = useToastStore((s) => s.addToast);

  const handleEdit = (field: string, currentValue: string | number | null) => {
    setEditing(field);
    setEditValue(String(currentValue ?? ''));
  };

  const handleSave = async () => {
    if (!editing) return;

    const data: Record<string, unknown> = {};
    if (editing === 'name') {
      data.name = editValue;
    } else if (editing === 'amount') {
      data.amount = editValue;
    } else {
      data[`${editing}_g`] = editValue || null;
    }

    try {
      await updateEntry(entry.id, data);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to update entry');
    }
    setEditing(null);
  };

  const handleDelete = async () => {
    try {
      await deleteEntry(entry.id);
      onUpdate();
      addToast('success', 'Entry deleted');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to delete entry');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') setEditing(null);
  };

  return (
    <div className="flex items-center gap-1.5 sm:gap-2 px-3 py-2 border-b-2 border-border text-sm last:border-b-0">
      <span className="w-10 sm:w-16 shrink-0 text-muted-foreground">{entry.time}</span>

      {caloriesEnabled && (
        <span className="w-10 sm:w-16 shrink-0">
          {canEdit && !autoCalcCalories && editing === 'amount' ? (
            <input className="bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} autoFocus inputMode="tel" />
          ) : (
            <button type="button" className={cn('bg-transparent border-0 p-0 text-sm text-foreground cursor-pointer tabular-nums', (!canEdit || autoCalcCalories) && 'cursor-default')} onClick={() => canEdit && !autoCalcCalories && handleEdit('amount', entry.amount)} disabled={!canEdit || autoCalcCalories}>
              {entry.amount}
            </button>
          )}
        </span>
      )}

      {enabledMacros.map((key) => {
        const val = entry.macros?.[key];
        return (
          <span key={key} className="w-8 sm:w-14 shrink-0">
            {canEdit && editing === key ? (
              <input className="bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} autoFocus inputMode="numeric" />
            ) : (
              <button type="button" className={cn('bg-transparent border-0 p-0 text-sm text-foreground cursor-pointer tabular-nums', !canEdit && 'cursor-default')} onClick={() => canEdit && handleEdit(key, val ?? null)} disabled={!canEdit}>
                {val != null ? val : '-'}
              </button>
            )}
          </span>
        );
      })}

      <span className="flex-1 min-w-[48px] truncate">
        {canEdit && editing === 'name' ? (
          <input className="bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} autoFocus />
        ) : (
          <button type="button" className={cn('bg-transparent border-0 p-0 text-sm text-foreground cursor-pointer text-left truncate w-full', !canEdit && 'cursor-default')} onClick={() => canEdit && handleEdit('name', entry.name)} disabled={!canEdit}>
            {entry.name || '\u2014'}
          </button>
        )}
      </span>

      {canEdit && (
        <span className="w-6 flex-shrink-0">
          <button type="button" className="bg-transparent border-0 p-0 text-muted-foreground hover:text-destructive text-lg cursor-pointer" onClick={handleDelete} title="Delete">&times;</button>
        </span>
      )}
    </div>
  );
}
