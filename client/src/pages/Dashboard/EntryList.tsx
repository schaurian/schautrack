import { useState } from 'react';
import type { Entry } from '@/types';
import { updateEntry, deleteEntry, createEntry } from '@/api/entries';
import { saveEntryAsFood } from '@/api/savedFoods';
import { useQueryClient } from '@tanstack/react-query';
import { MACRO_LABELS } from '@/lib/macros';
import { cn } from '@/lib/utils';
import { useToastStore } from '@/stores/toastStore';
import { MacroPill, MacroPillEditing } from '@/components/ui/MacroPill';

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
    <div className="flex flex-col gap-1.5 p-2">
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
          onSaveAsFood={() => {
            queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
          }}
        />
      ))}
    </div>
  );
}

function EntryRow({ entry, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories, onUpdate, onSaveAsFood }: {
  entry: Entry;
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  onUpdate: () => void;
  onSaveAsFood: () => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [savingFood, setSavingFood] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  const handleSaveAsFood = async () => {
    if (savingFood) return;
    setSavingFood(true);
    try {
      await saveEntryAsFood(entry.id);
      onSaveAsFood();
      addToast('success', `Saved "${entry.name || 'entry'}" as quick-add`);
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save');
    }
    setSavingFood(false);
  };

  const handleEdit = (field: string, currentValue: string | number | null) => {
    if (!canEdit) return;
    setEditing(field);
    setEditValue(String(currentValue ?? ''));
  };

  const handleSave = async () => {
    if (!editing) return;

    const data: Record<string, unknown> = {};
    if (editing === 'name') {
      data.name = editValue;
    } else if (editing === 'amount') {
      data.amount = !editValue || editValue === '0' ? null : editValue;
    } else {
      data[`${editing}_g`] = !editValue || editValue === '0' ? null : editValue;
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
    // Snapshot the entry so an accidental delete can be undone. The recreated
    // entry gets a new id (the server has no soft-delete) — an acceptable
    // trade-off, matching the saved-foods Undo pattern.
    const snapshot: Parameters<typeof createEntry>[0] = { entry_date: entry.date };
    if (entry.name) snapshot.entry_name = entry.name;
    if (entry.amount) snapshot.amount = entry.amount;
    if (entry.macros) {
      const m = entry.macros;
      if (m.protein != null) snapshot.protein_g = m.protein;
      if (m.carbs != null) snapshot.carbs_g = m.carbs;
      if (m.fat != null) snapshot.fat_g = m.fat;
      if (m.fiber != null) snapshot.fiber_g = m.fiber;
      if (m.sugar != null) snapshot.sugar_g = m.sugar;
    }

    try {
      await deleteEntry(entry.id);
      onUpdate();
      addToast('success', 'Entry deleted', {
        label: 'Undo',
        onClick: async () => {
          try {
            await createEntry(snapshot);
            onUpdate();
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : 'Restore failed');
          }
        },
      });
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to delete entry');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') setEditing(null);
  };

  const hasMacros = caloriesEnabled || enabledMacros.length > 0;

  return (
    <div className={cn(
      'rounded-[10px] border border-border bg-white/[0.015] transition-[border-color,background] duration-150 hover:bg-white/[0.04] hover:border-white/10',
      editing && 'border-[#0ea5e9]/40 shadow-[0_0_0_1px_rgba(14,165,233,0.25),0_8px_22px_rgba(2,18,45,0.4)]',
    )}>
      {/* Row 1: Name + Time + Delete */}
      <div className="flex items-center gap-1.5 px-3 py-2">
        <span className="flex-1 min-w-0 truncate">
          {editing === 'name' ? (
            <input className="bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} autoFocus />
          ) : (
            <button
              type="button"
              className={cn('bg-transparent border border-transparent px-2 py-0.5 text-[15px] font-semibold text-foreground text-left truncate w-full rounded-md transition-colors', canEdit ? 'cursor-pointer hover:text-[#0ea5e9]' : 'cursor-default')}
              onClick={() => handleEdit('name', entry.name)}
              disabled={!canEdit}
            >
              {entry.name || '\u2014'}
            </button>
          )}
        </span>
        <span className="text-xs text-muted-foreground tabular-nums shrink-0 opacity-85">{entry.time}</span>
        {canEdit && entry.name && (
          <button
            type="button"
            className="size-7 flex items-center justify-center rounded-[10px] border border-border text-muted-foreground hover:text-primary hover:border-primary/40 hover:bg-primary/5 transition-colors cursor-pointer shrink-0 disabled:opacity-40"
            onClick={handleSaveAsFood}
            disabled={savingFood}
            aria-label="Save as quick-add"
            title="Save as quick-add"
          >
            {savingFood ? (
              <span className="size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
            ) : (
              <svg aria-hidden="true" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
              </svg>
            )}
          </button>
        )}
        {canEdit && (
          <button type="button" className="size-7 flex items-center justify-center rounded-[10px] border border-destructive/30 bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors cursor-pointer shrink-0" onClick={handleDelete} aria-label="Delete entry" title="Delete">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 6L6 18" /><path d="M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Row 2: Macro pills */}
      {hasMacros && (
        <div className="flex flex-wrap gap-1.5 px-3 pb-2.5">
          {caloriesEnabled && (
            editing === 'amount' ? (
              <MacroPillEditing
                macroKey="kcal"
                label="Calories"
                unit="kcal"
                editValue={editValue}
                onChange={setEditValue}
                onSave={handleSave}
                onKeyDown={handleKeyDown}
                inputMode="tel"
              />
            ) : (
              <MacroPill
                macroKey="kcal"
                label="Calories"
                value={entry.amount || null}
                unit="kcal"
                onClick={() => canEdit && !autoCalcCalories && handleEdit('amount', entry.amount)}
                canEdit={canEdit && !autoCalcCalories}
              />
            )
          )}
          {enabledMacros.map((key) => {
            const val = entry.macros?.[key];
            const label = MACRO_LABELS[key as keyof typeof MACRO_LABELS]?.label || key;
            return editing === key ? (
              <MacroPillEditing
                key={key}
                macroKey={key}
                label={label}
                unit="g"
                editValue={editValue}
                onChange={setEditValue}
                onSave={handleSave}
                onKeyDown={handleKeyDown}
              />
            ) : (
              <MacroPill
                key={key}
                macroKey={key}
                label={label}
                value={val ?? null}
                unit="g"
                onClick={() => handleEdit(key, val ?? null)}
                canEdit={canEdit}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
