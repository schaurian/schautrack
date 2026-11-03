import { useLayoutEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Entry } from '@/types';
import { updateEntry, deleteEntry, createEntry } from '@/api/entries';
import { saveEntryAsFood } from '@/api/savedFoods';
import { ApiError } from '@/api/client';
import { useQueryClient } from '@tanstack/react-query';
import { MACRO_LABELS } from '@/lib/macros';
import { entryFieldErrorText, parseInlineEdit, type FieldError } from '@/lib/entryValidation';
import { cn } from '@/lib/utils';
import { nextToastSeq, useToastStore } from '@/stores/toastStore';
import { MacroPill, MacroPillEditing } from '@/components/ui/MacroPill';
import { InlineEditInput } from '@/components/ui/InlineEditInput';

// Deleting an entry reflows the list, so the next row's delete button slides
// up under the pointer: a double-click or double-tap meant for one entry would
// remove two. A delete is dropped, whichever row it came from, if it arrives
// within this window of the previous delete OR of the row the user deleted
// actually leaving the list. The second clock matters: the reflow only happens
// once the delete and the refetch have both round-tripped (~370ms on a local
// stack), so a window counted from the first tap alone has mostly expired by
// the time the row moves. Rows that disappear for any other reason (an SSE
// refetch from another device, switching day) never arm the guard.
export const DELETE_REPEAT_GUARD_MS = 400;

interface Props {
  entries: Entry[];
  /** The day the list shows. A change means a different list, not a reflow. */
  date?: string;
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
}

export default function EntryList({ entries, date, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const lastDeleteAt = useRef(Number.NEGATIVE_INFINITY);
  const lastReflowAt = useRef(Number.NEGATIVE_INFINITY);
  // Ids this list's own delete buttons removed and that are still rendered.
  const pendingDeletes = useRef<Set<number>>(new Set());
  const shownDate = useRef(date);
  useLayoutEffect(() => {
    // Switching day swaps the whole list: a pending id vanishing then is not
    // the deleted row reflowing out from under the pointer.
    if (date !== shownDate.current) {
      shownDate.current = date;
      pendingDeletes.current.clear();
      return;
    }
    if (pendingDeletes.current.size === 0) return;
    const ids = new Set(entries.map((e) => e.id));
    for (const id of pendingDeletes.current) {
      if (!ids.has(id)) {
        pendingDeletes.current.delete(id);
        lastReflowAt.current = Date.now();
      }
    }
  }, [entries, date]);
  const claimDelete = (id: number) => {
    const now = Date.now();
    // Already being deleted: a second DELETE could only 404.
    if (pendingDeletes.current.has(id)) return false;
    if (now - lastDeleteAt.current < DELETE_REPEAT_GUARD_MS) return false;
    if (now - lastReflowAt.current < DELETE_REPEAT_GUARD_MS) return false;
    lastDeleteAt.current = now;
    pendingDeletes.current.add(id);
    return true;
  };
  // A failed delete leaves its row in place, so it must not arm the guard later.
  const forgetDelete = (id: number) => {
    pendingDeletes.current.delete(id);
  };

  if (entries.length === 0) {
    return <p className="text-center text-sm text-muted-foreground py-4">{t('entries.emptyList')}</p>;
  }

  return (
    <div className="flex flex-col divide-y divide-divider">
      {entries.map((entry) => (
        <EntryRow
          key={entry.id}
          entry={entry}
          canEdit={canEdit}
          enabledMacros={enabledMacros}
          caloriesEnabled={caloriesEnabled}
          autoCalcCalories={autoCalcCalories}
          claimDelete={claimDelete}
          forgetDelete={forgetDelete}
          onUpdate={() => {
            // See Dashboard.tsx: the SSE echo only reaches this tab when the
            // write hit the instance holding its stream, so refresh locally too.
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

function EntryRow({ entry, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories, claimDelete, forgetDelete, onUpdate, onSaveAsFood }: {
  entry: Entry;
  claimDelete: (id: number) => boolean;
  forgetDelete: (id: number) => void;
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  onUpdate: () => void;
  onSaveAsFood: () => void;
}) {
  const { t, i18n } = useTranslation('dashboard');
  const lang = i18n.resolvedLanguage || i18n.language || 'en';
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [editError, setEditError] = useState<FieldError | null>(null);
  const editErrorId = `entry-${entry.id}-edit-error`;
  const [savingFood, setSavingFood] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  const handleSaveAsFood = async () => {
    if (savingFood) return;
    setSavingFood(true);
    try {
      await saveEntryAsFood(entry.id);
      onSaveAsFood();
      addToast('success', t('entries.toastSavedAsQuickAdd', { name: entry.name || t('entries.unnamedEntryFallback') }));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('entries.toastSaveFailed'));
    }
    setSavingFood(false);
  };

  const handleEdit = (field: string, currentValue: string | number | null) => {
    if (!canEdit) return;
    setEditing(field);
    setEditValue(String(currentValue ?? ''));
    setEditError(null);
  };

  const handleEditChange = (v: string) => {
    setEditValue(v);
    setEditError(null);
  };

  const handleSave = async () => {
    if (!editing) return;

    const data: Record<string, unknown> = {};
    if (editing === 'name') {
      data.name = editValue;
    } else {
      // Evaluated here, with the active language's separators, and sent as a
      // number: the raw string reached the server's parser, which reads
      // English separators, so German "12,5" kcal was stored as 125.
      const parsed = parseInlineEdit(editing === 'amount' ? 'calories' : 'macro', editValue, lang);
      if (!parsed.ok) {
        setEditError(parsed);
        return;
      }
      // 0 clears the value, as an empty field does.
      data[editing === 'amount' ? 'amount' : `${editing}_g`] = parsed.value === 0 ? null : parsed.value;
    }

    try {
      await updateEntry(entry.id, data);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('entries.toastUpdateFailed'));
    }
    setEditing(null);
  };

  const handleDelete = async () => {
    if (deleting || !claimDelete(entry.id)) return;
    setDeleting(true);
    // Taken at click time: the toast follows the delete clicked last, not the
    // one whose response happened to arrive last.
    const seq = nextToastSeq();
    // Snapshot the entry so an accidental delete can be undone. The recreated
    // entry gets a new id (the server has no soft-delete) — an acceptable
    // trade-off, matching the saved-foods Undo pattern. The delete response's
    // `restore` body replaces this snapshot when present: it carries the
    // logged time and macros hidden from this list, which the snapshot lacks.
    let snapshot: Parameters<typeof createEntry>[0] = { entry_date: entry.date };
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
      const res = await deleteEntry(entry.id);
      if (res?.restore) snapshot = res.restore;
      onUpdate();
      addToast('success', t('entries.toastDeleted'), {
        label: t('entries.undoLabel'),
        onClick: async () => {
          try {
            await createEntry(snapshot);
            onUpdate();
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : t('entries.toastRestoreFailed'));
          }
        },
      }, { replaceKey: 'entry-delete', seq });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Already gone (deleted from another device, or an earlier request of
        // ours got there first): the outcome the user asked for, so refresh
        // instead of reporting a failure. No Undo — this tap deleted nothing.
        onUpdate();
      } else {
        forgetDelete(entry.id);
        addToast('error', err instanceof Error ? err.message : t('entries.toastDeleteFailed'));
      }
    } finally {
      setDeleting(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') {
      setEditing(null);
      setEditError(null);
    }
  };

  const hasMacros = caloriesEnabled || enabledMacros.length > 0;

  return (
    <div className={cn(
      'py-0.5 transition-colors duration-150 hover:bg-white/[0.02]',
      editing && 'rounded-[10px] bg-[#0ea5e9]/5',
    )}>
      {/* Row 1: Name + Time + Delete */}
      <div className="flex items-center gap-1.5 px-1 py-2">
        {/* Typography lives on the wrapper so the edit input inherits it and the text doesn't jump. */}
        <span className="flex-1 min-w-0 truncate text-[15px] font-semibold">
          {editing === 'name' ? (
            <InlineEditInput className="px-2 py-0.5 w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} autoFocus />
          ) : (
            <button
              type="button"
              className={cn('bg-transparent border border-transparent px-2 py-0.5 text-foreground text-left truncate w-full rounded-md transition-colors', canEdit ? 'cursor-pointer hover:text-[#0ea5e9]' : 'cursor-default')}
              onClick={() => handleEdit('name', entry.name)}
              disabled={!canEdit}
            >
              {entry.name || '\u2014'}
            </button>
          )}
        </span>
        <span className="text-xs text-muted-foreground tabular-nums shrink-0 opacity-85">{entry.time}</span>
        {/* Both actions are 44x44 hit areas around 28px visuals; -my-2 keeps
            the row height unchanged. Delete sits an extra 0.5rem away from
            save-as-quick-add so a tap aimed at the frequently used button
            cannot land on the destructive one. */}
        {canEdit && entry.name && (
          <button
            type="button"
            className="group/save -my-2 flex size-11 shrink-0 cursor-pointer items-center justify-center disabled:opacity-40"
            onClick={handleSaveAsFood}
            disabled={savingFood}
            aria-label={t('entries.saveAsQuickAddLabel')}
            title={t('entries.saveAsQuickAddLabel')}
          >
            <span aria-hidden="true" className="flex size-7 items-center justify-center rounded-[10px] border border-border text-muted-foreground transition-colors group-hover/save:border-primary/40 group-hover/save:bg-primary/5 group-hover/save:text-primary">
              {savingFood ? (
                <span className="size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                <svg aria-hidden="true" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
                </svg>
              )}
            </span>
          </button>
        )}
        {canEdit && (
          <button type="button" className="group/delete -my-2 -mr-2 ml-2 flex size-11 shrink-0 cursor-pointer items-center justify-center aria-disabled:cursor-default aria-disabled:opacity-40" onClick={handleDelete} aria-disabled={deleting || undefined} aria-label={t('entries.deleteEntryAriaLabel')} title={t('entries.deleteTitle')}>
            <span aria-hidden="true" className="flex size-7 items-center justify-center rounded-[10px] border border-destructive/30 bg-destructive/10 text-destructive transition-colors group-hover/delete:bg-destructive/20">
              <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6L6 18" /><path d="M6 6l12 12" />
              </svg>
            </span>
          </button>
        )}
      </div>

      {/* Row 2: Macro pills */}
      {hasMacros && (
        <div className="flex flex-wrap gap-1.5 px-1 pb-2">
          {caloriesEnabled && (
            editing === 'amount' ? (
              <MacroPillEditing
                macroKey="kcal"
                label={t('entries.caloriesLabel')}
                unit="kcal"
                editValue={editValue}
                onChange={handleEditChange}
                onSave={handleSave}
                onKeyDown={handleKeyDown}
                inputMode="tel"
                invalid={!!editError}
                describedBy={editErrorId}
              />
            ) : (
              <MacroPill
                macroKey="kcal"
                label={t('entries.caloriesLabel')}
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
                onChange={handleEditChange}
                onSave={handleSave}
                onKeyDown={handleKeyDown}
                invalid={!!editError}
                describedBy={editErrorId}
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
      {editError && (
        <p id={editErrorId} className="px-1 pb-2 text-xs text-destructive">
          {entryFieldErrorText(t, editError)}
        </p>
      )}
    </div>
  );
}
