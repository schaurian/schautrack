import { useEffect, useLayoutEffect, useRef, useState } from 'react';
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
  /** id of the list's heading; focus lands there when the last entry is deleted. */
  headingId?: string;
}

export default function EntryList({ entries, date, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories, headingId }: Props) {
  const { t } = useTranslation('dashboard');
  const queryClient = useQueryClient();
  const listRef = useRef<HTMLDivElement>(null);
  // Polite live region for inline-edit saves (rendered below).
  const [announcement, setAnnouncement] = useState('');
  const announceTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(announceTimer.current), []);
  const announce = (msg: string) => {
    clearTimeout(announceTimer.current);
    setAnnouncement(msg);
    // Cleared again so that saving the same field twice is announced twice.
    announceTimer.current = setTimeout(() => setAnnouncement(''), SAVED_FEEDBACK_MS);
  };
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

  // The deleted row's button is about to unmount, which would drop focus to
  // <body> and send keyboard and screen-reader users back to the top of the
  // page. Move it to the same control on the next row, else the previous row,
  // else (the list is now empty) the list heading. Only when focus is still on
  // the row that was deleted — the request can take long enough for the user to
  // have moved on.
  const handleDeleted = (row: HTMLElement) => {
    const active = document.activeElement;
    if (active && active !== document.body && !row.contains(active)) return;
    const buttons = Array.from(listRef.current?.querySelectorAll<HTMLElement>('[data-entry-delete]') ?? []);
    const i = buttons.findIndex((b) => row.contains(b));
    const target = buttons[i + 1] ?? buttons[i - 1] ?? (headingId ? document.getElementById(headingId) : null);
    target?.focus();
  };

  return (
    <>
      {/* Always the first child of the same fragment, so React keeps this one
          node mounted when the list empties or fills: a live region that
          appears together with its text is often not announced at all. */}
      <p className="sr-only" aria-live="polite">{announcement}</p>
      {entries.length === 0 ? (
        <p className="text-center text-sm text-muted-foreground py-4">{t('entries.emptyList')}</p>
      ) : (
        <div ref={listRef} className="flex flex-col divide-y divide-divider">
          {entries.map((entry) => (
            <EntryRow
              key={entry.id}
              entry={entry}
              canEdit={canEdit}
              enabledMacros={enabledMacros}
              caloriesEnabled={caloriesEnabled}
              autoCalcCalories={autoCalcCalories}
              onUpdate={() => {
                // See Dashboard.tsx: the SSE echo only reaches this tab when the
                // write hit the instance holding its stream, so refresh locally too.
                queryClient.invalidateQueries({ queryKey: ['dashboard'] });
                queryClient.invalidateQueries({ queryKey: ['day-entries'] });
              }}
              claimDelete={claimDelete}
              forgetDelete={forgetDelete}
              onSaveAsFood={() => {
                queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
              }}
              onDeleted={handleDeleted}
              onSaved={announce}
            />
          ))}
        </div>
      )}
    </>
  );
}

const SAVED_FEEDBACK_MS = 2000;

function EntryRow({ entry, canEdit, enabledMacros, caloriesEnabled, autoCalcCalories, claimDelete, forgetDelete, onUpdate, onSaveAsFood, onDeleted, onSaved }: {
  entry: Entry;
  claimDelete: (id: number) => boolean;
  forgetDelete: (id: number) => void;
  canEdit: boolean;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  onUpdate: () => void;
  onSaveAsFood: () => void;
  onDeleted: (row: HTMLElement) => void;
  onSaved: (announcement: string) => void;
}) {
  const { t, i18n } = useTranslation('dashboard');
  const lang = i18n.resolvedLanguage || i18n.language || 'en';
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [editError, setEditError] = useState<FieldError | null>(null);
  const editErrorId = `entry-${entry.id}-edit-error`;
  const [savingFood, setSavingFood] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [justSaved, setJustSaved] = useState(false);
  const addToast = useToastStore((s) => s.addToast);
  const rowRef = useRef<HTMLDivElement>(null);
  const savedTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(savedTimer.current), []);
  // Field whose display control should get focus back once its input is gone.
  // Set only when the edit is ended from the keyboard (Enter/Escape); a blur
  // means focus already went somewhere the user chose.
  const refocusField = useRef<string | null>(null);
  useEffect(() => {
    if (editing !== null || !refocusField.current) return;
    rowRef.current?.querySelector<HTMLElement>(`[data-edit-field="${refocusField.current}"]`)?.focus();
    refocusField.current = null;
  }, [editing]);

  const entryName = entry.name || t('entries.unnamedEntryFallback');
  const fieldLabel = (field: string) =>
    field === 'name' ? t('entries.nameFieldLabel')
      : field === 'amount' ? t('entries.caloriesLabel')
        : MACRO_LABELS[field as keyof typeof MACRO_LABELS]?.label || field;
  const editAriaLabel = (field: string) => t('entries.editFieldAriaLabel', { field: fieldLabel(field), name: entryName });

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
        // The input stays open for a fix; a later blur-save must not pull
        // focus back to the pill the way a keyboard-ended edit does.
        refocusField.current = null;
        return;
      }
      // 0 clears the value, as an empty field does.
      data[editing === 'amount' ? 'amount' : `${editing}_g`] = parsed.value === 0 ? null : parsed.value;
    }

    try {
      await updateEntry(entry.id, data);
      onUpdate();
      // Adding an entry confirms with a toast; an inline edit used to save in
      // silence. A brief check next to the time, plus a polite announcement.
      clearTimeout(savedTimer.current);
      setJustSaved(true);
      savedTimer.current = setTimeout(() => setJustSaved(false), SAVED_FEEDBACK_MS);
      onSaved(t('entries.savedAnnouncement', { field: fieldLabel(editing), name: entryName }));
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
      if (rowRef.current) onDeleted(rowRef.current);
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
        // The row is about to leave the list all the same, so move focus.
        if (rowRef.current) onDeleted(rowRef.current);
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
    if (e.key === 'Enter') {
      refocusField.current = editing;
      handleSave();
    }
    if (e.key === 'Escape') {
      refocusField.current = editing;
      setEditing(null);
      setEditError(null);
    }
  };

  const hasMacros = caloriesEnabled || enabledMacros.length > 0;

  return (
    <div ref={rowRef} className={cn(
      'py-0.5 transition-colors duration-150 hover:bg-white/[0.02]',
      editing && 'rounded-[10px] bg-[#0ea5e9]/5',
    )}>
      {/* Row 1: Name + Time + Delete */}
      <div className="flex items-center gap-1.5 px-1 py-2">
        {/* Typography lives on the wrapper so the edit input inherits it and the text doesn't jump. */}
        <span className="flex-1 min-w-0 truncate text-[15px] font-semibold">
          {editing === 'name' ? (
            <InlineEditInput className="px-2 py-0.5 w-full" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={handleSave} onKeyDown={handleKeyDown} aria-label={editAriaLabel('name')} autoFocus />
          ) : (
            <button
              type="button"
              className={cn('bg-transparent border border-transparent px-2 py-0.5 text-foreground text-left truncate w-full rounded-md transition-colors', canEdit ? 'cursor-pointer hover:text-[#0ea5e9]' : 'cursor-default')}
              onClick={() => handleEdit('name', entry.name)}
              disabled={!canEdit}
              data-edit-field="name"
            >
              {entry.name || '\u2014'}
            </button>
          )}
        </span>
        {justSaved && (
          // Visual only: the list's live region carries the announcement.
          <span className="inline-flex shrink-0 items-center gap-0.5 text-xs font-medium text-success" aria-hidden="true" data-testid="entry-saved">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 6L9 17l-5-5" />
            </svg>
            {t('entries.savedLabel')}
          </span>
        )}
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
          <button type="button" className="group/delete -my-2 -mr-2 ml-2 flex size-11 shrink-0 cursor-pointer items-center justify-center aria-disabled:cursor-default aria-disabled:opacity-40" onKeyDown={(e) => {
              // A held key auto-repeats, and Enter activates the button on
              // every repeated keydown. The reflow guard above only spans
              // DELETE_REPEAT_GUARD_MS, so without this a held Enter keeps
              // deleting the row focus lands on once the window has passed.
              if (e.repeat && (e.key === 'Enter' || e.key === ' ')) e.preventDefault();
            }}
            onClick={handleDelete} data-entry-delete aria-disabled={deleting || undefined} aria-label={t('entries.deleteEntryAriaLabel')} title={t('entries.deleteTitle')}>
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
                aria-label={editAriaLabel('amount')}
              />
            ) : (
              <MacroPill
                macroKey="kcal"
                label={t('entries.caloriesLabel')}
                value={entry.amount || null}
                unit="kcal"
                onClick={() => canEdit && !autoCalcCalories && handleEdit('amount', entry.amount)}
                canEdit={canEdit && !autoCalcCalories}
                editField="amount"
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
                aria-label={editAriaLabel(key)}
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
                editField={key}
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
