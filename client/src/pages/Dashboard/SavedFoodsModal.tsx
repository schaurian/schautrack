import { useState, useMemo, useEffect, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { listSavedFoods, trackSavedFood, deleteSavedFood, createSavedFood, updateSavedFood } from '@/api/savedFoods';
import type { SavedFoodPayload } from '@/api/savedFoods';
import { deleteEntry } from '@/api/entries';
import { useToastStore } from '@/stores/toastStore';
import { useAuthStore } from '@/stores/authStore';
import { Button } from '@/components/ui/Button';
import { MacroPill, MacroPillEditing } from '@/components/ui/MacroPill';
import { MACRO_LABELS, getEnabledMacros } from '@/lib/macros';
import { cn } from '@/lib/utils';
import type { SavedFood } from '@/types';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  selectedDate?: string;
}

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2 py-1.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring';

export default function SavedFoodsModal({ isOpen, onClose, selectedDate }: Props) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const user = useAuthStore((s) => s.user);
  const enabledMacros = useMemo(
    () => getEnabledMacros(user?.macrosEnabled ?? {}) as string[],
    [user]
  );
  const caloriesEnabled = user?.macrosEnabled?.calories !== false;

  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);
  const [draftName, setDraftName] = useState('');
  const draftRef = useRef<HTMLInputElement>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['savedFoods'],
    queryFn: listSavedFoods,
    enabled: isOpen,
  });

  useEffect(() => {
    if (!isOpen) {
      setSearch('');
      setCreating(false);
      setDraftName('');
    }
  }, [isOpen]);

  useEffect(() => {
    if (creating) draftRef.current?.focus();
  }, [creating]);

  if (!isOpen) return null;

  const all = data?.savedFoods ?? [];
  const filtered = search
    ? all.filter((f) => f.name.toLowerCase().includes(search.toLowerCase()))
    : all;

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['day-entries'] });
  };

  const cancelDraft = () => {
    setCreating(false);
    setDraftName('');
  };

  const commitDraft = async () => {
    const name = draftName.trim();
    if (!name) {
      cancelDraft();
      return;
    }
    const payload: SavedFoodPayload = { name };
    try {
      await createSavedFood(payload);
      cancelDraft();
      invalidate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save');
    }
  };

  const handleDraftKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') commitDraft();
    if (e.key === 'Escape') cancelDraft();
  };

  return (
    <div className="fixed inset-0 z-[150] flex items-center justify-center bg-background/80 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="relative w-full max-w-2xl max-h-[90vh] flex flex-col rounded-xl border-2 border-border bg-card overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b-2 border-border">
          <h2 className="text-base font-semibold">Saved foods</h2>
          <button
            type="button"
            className="text-muted-foreground hover:text-foreground bg-transparent border-0 text-2xl leading-none cursor-pointer"
            onClick={onClose}
          >
            &times;
          </button>
        </div>

        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
          <input
            type="text"
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={inputClass}
          />
          {!creating && (
            <Button size="sm" variant="default" onClick={() => setCreating(true)}>+ New</Button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-2">
          {creating && (
            <div className="rounded-[10px] border border-[#0ea5e9]/40 bg-white/[0.015] mb-1.5 shadow-[0_0_0_1px_rgba(14,165,233,0.25),0_8px_22px_rgba(2,18,45,0.4)]">
              <div className="flex items-center gap-1.5 px-3 py-2">
                <input
                  ref={draftRef}
                  type="text"
                  className="flex-1 bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none"
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  onBlur={commitDraft}
                  onKeyDown={handleDraftKey}
                  placeholder="Name your saved food, then click pills to add values…"
                  maxLength={80}
                />
                <Button size="sm" variant="ghost" onClick={cancelDraft}>Cancel</Button>
              </div>
            </div>
          )}

          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
            </div>
          ) : filtered.length === 0 && !creating ? (
            <p className="text-center text-sm text-muted-foreground py-8">
              {search ? 'No matches.' : 'No saved foods yet. Use the "Save" button on the entry form, or hit "+ New".'}
            </p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {filtered.map((food) => (
                <SavedFoodRow
                  key={food.id}
                  food={food}
                  enabledMacros={enabledMacros}
                  caloriesEnabled={caloriesEnabled}
                  selectedDate={selectedDate}
                  onChange={invalidate}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface RowProps {
  food: SavedFood;
  enabledMacros: string[];
  caloriesEnabled: boolean;
  selectedDate?: string;
  onChange: () => void;
}

// One field is edited at a time; null means display mode. "name" and "emoji"
// edit text, "amount" edits calories, anything else is a macro key.
type EditField = 'name' | 'emoji' | 'amount' | 'protein' | 'carbs' | 'fat' | 'fiber' | 'sugar' | null;

function SavedFoodRow({ food, enabledMacros, caloriesEnabled, selectedDate, onChange }: RowProps) {
  const addToast = useToastStore((s) => s.addToast);
  const [editing, setEditing] = useState<EditField>(null);
  const [editValue, setEditValue] = useState('');
  const [busy, setBusy] = useState(false);

  const beginEdit = (field: EditField, current: string | number | null) => {
    if (field === null) return;
    setEditing(field);
    setEditValue(current == null ? '' : String(current));
  };

  const save = async (field: EditField, raw: string) => {
    if (field === null) return;
    const payload: SavedFoodPayload = {};
    if (field === 'name') {
      const v = raw.trim();
      if (!v) {
        addToast('error', 'Name is required');
        setEditing(null);
        return;
      }
      payload.name = v;
    } else if (field === 'emoji') {
      payload.emoji = raw.trim() || null;
    } else if (field === 'amount') {
      payload.amount = raw.trim() === '' ? null : Number(raw);
    } else {
      const n = raw.trim() === '' ? null : Number(raw);
      (payload as Record<string, unknown>)[`${field}_g`] = n;
    }
    try {
      await updateSavedFood(food.id, payload);
      onChange();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to update');
    }
    setEditing(null);
  };

  const handleSave = () => save(editing, editValue);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') setEditing(null);
  };

  const handleDelete = async () => {
    setBusy(true);
    // Snapshot so Undo can re-create the row. use_count/last_used_at are not
    // preserved — acceptable trade-off vs. a soft-delete column on the table.
    const snapshot = {
      name: food.name,
      emoji: food.emoji,
      amount: food.amount,
      protein_g: food.macros.protein,
      carbs_g: food.macros.carbs,
      fat_g: food.macros.fat,
      fiber_g: food.macros.fiber,
      sugar_g: food.macros.sugar,
    };
    try {
      await deleteSavedFood(food.id);
      onChange();
      addToast('success', `Deleted ${food.name}`, {
        label: 'Undo',
        onClick: async () => {
          try {
            await createSavedFood(snapshot);
            onChange();
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : 'Restore failed');
          }
        },
      });
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to delete');
    }
    setBusy(false);
  };

  const handleTrack = async () => {
    setBusy(true);
    try {
      const res = await trackSavedFood(food.id, selectedDate);
      addToast('success', `Tracked ${food.name}`, {
        label: 'Undo',
        onClick: async () => {
          try {
            await deleteEntry(res.entry.id);
            onChange();
          } catch (err) {
            addToast('error', err instanceof Error ? err.message : 'Undo failed');
          }
        },
      });
      onChange();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to track');
    }
    setBusy(false);
  };

  const hasPills = caloriesEnabled || enabledMacros.length > 0;

  return (
    <div className={cn(
      'group rounded-[10px] border border-border bg-white/[0.015] transition-[border-color,background] duration-150 hover:bg-white/[0.04] hover:border-white/10',
      editing && 'border-[#0ea5e9]/40 shadow-[0_0_0_1px_rgba(14,165,233,0.25),0_8px_22px_rgba(2,18,45,0.4)]',
    )}>
      {/* Row 1: emoji + name + badges + actions */}
      <div className="flex items-center gap-1.5 px-3 py-2">
        {/* Emoji slot — only rendered when an emoji is set. No gutter when empty. */}
        {editing === 'emoji' ? (
          <input
            className="bg-muted/50 border border-ring rounded-md px-1.5 py-0.5 text-base outline-none w-12 text-center"
            value={editValue}
            onChange={(e) => setEditValue(e.target.value)}
            onBlur={handleSave}
            onKeyDown={handleKeyDown}
            maxLength={4}
            autoFocus
          />
        ) : food.emoji ? (
          <button
            type="button"
            className="size-7 flex items-center justify-center rounded-md border border-transparent text-lg leading-none shrink-0 bg-transparent cursor-pointer hover:border-border hover:bg-white/[0.04]"
            onClick={() => beginEdit('emoji', food.emoji)}
            title="Change emoji"
          >
            {food.emoji}
          </button>
        ) : null}

        {/* Name */}
        <span className="flex-1 min-w-0 truncate">
          {editing === 'name' ? (
            <input
              className="bg-muted/50 border border-ring rounded-md px-2 py-0.5 text-sm text-foreground outline-none w-full"
              value={editValue}
              onChange={(e) => setEditValue(e.target.value)}
              onBlur={handleSave}
              onKeyDown={handleKeyDown}
              maxLength={80}
              autoFocus
            />
          ) : (
            <button
              type="button"
              className="bg-transparent border border-transparent px-2 py-0.5 text-[15px] font-semibold text-foreground text-left truncate w-full rounded-md transition-colors cursor-pointer hover:text-[#0ea5e9]"
              onClick={() => beginEdit('name', food.name)}
            >
              {food.name}
            </button>
          )}
        </span>

        {food.use_count > 0 && (
          <span className="text-[10px] tabular-nums text-muted-foreground shrink-0">{food.use_count}×</span>
        )}

        {selectedDate && (
          <Button size="sm" variant="default" onClick={handleTrack} disabled={busy}>Track</Button>
        )}

        <button
          type="button"
          className="size-7 flex items-center justify-center rounded-[10px] border border-destructive/30 bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors cursor-pointer shrink-0 disabled:opacity-40"
          onClick={handleDelete}
          disabled={busy}
          title="Delete"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 6L6 18" /><path d="M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Row 2: macro pills */}
      {hasPills && (
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
                value={food.amount ?? null}
                unit="kcal"
                onClick={() => beginEdit('amount', food.amount)}
              />
            )
          )}
          {enabledMacros.map((k) => {
            const val = food.macros[k as keyof typeof food.macros];
            const label = MACRO_LABELS[k as keyof typeof MACRO_LABELS]?.label || k;
            return editing === k ? (
              <MacroPillEditing
                key={k}
                macroKey={k}
                label={label}
                unit="g"
                editValue={editValue}
                onChange={setEditValue}
                onSave={handleSave}
                onKeyDown={handleKeyDown}
              />
            ) : (
              <MacroPill
                key={k}
                macroKey={k}
                label={label}
                value={val ?? null}
                unit="g"
                onClick={() => beginEdit(k as EditField, val ?? null)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
