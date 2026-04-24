import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { createTemplate, updateTemplate } from '@/api/templates';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import type { MealTemplate, MealTemplateItemInput } from '@/types';

interface EditorItem {
  entry_name: string;
  amount: string;
  protein_g: string;
  carbs_g: string;
  fat_g: string;
  fiber_g: string;
  sugar_g: string;
}

const EMPTY_ITEM: EditorItem = {
  entry_name: '',
  amount: '',
  protein_g: '',
  carbs_g: '',
  fat_g: '',
  fiber_g: '',
  sugar_g: '',
};

function toEditorItem(it: {
  entry_name?: string | null;
  amount: number;
  protein_g?: number | null;
  carbs_g?: number | null;
  fat_g?: number | null;
  fiber_g?: number | null;
  sugar_g?: number | null;
}): EditorItem {
  const toStr = (n: number | null | undefined) => (n == null ? '' : String(n));
  return {
    entry_name: it.entry_name || '',
    amount: it.amount === 0 ? '' : String(it.amount),
    protein_g: toStr(it.protein_g),
    carbs_g: toStr(it.carbs_g),
    fat_g: toStr(it.fat_g),
    fiber_g: toStr(it.fiber_g),
    sugar_g: toStr(it.sugar_g),
  };
}

function parseOptionalInt(raw: string): number | null {
  const t = raw.trim();
  if (t === '') return null;
  const n = Number(t);
  if (!Number.isFinite(n) || Math.round(n) !== n) return NaN;
  return n;
}

interface Props {
  isOpen: boolean;
  template: MealTemplate | null;
  presetItems?: EditorItem[];
  presetName?: string;
  onClose: () => void;
  onSaved: () => void;
}

export default function TemplateEditor({
  isOpen,
  template,
  presetItems,
  presetName,
  onClose,
  onSaved,
}: Props) {
  const addToast = useToastStore((s) => s.addToast);
  const isEdit = !!template;

  const [name, setName] = useState('');
  const [isFavorite, setIsFavorite] = useState(false);
  const [items, setItems] = useState<EditorItem[]>([{ ...EMPTY_ITEM }]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    if (template) {
      setName(template.name);
      setIsFavorite(template.is_favorite);
      setItems(template.items.length > 0 ? template.items.map(toEditorItem) : [{ ...EMPTY_ITEM }]);
    } else {
      setName(presetName ?? '');
      setIsFavorite(false);
      setItems(presetItems && presetItems.length > 0 ? presetItems : [{ ...EMPTY_ITEM }]);
    }
  }, [isOpen, template, presetName, presetItems]);

  const setItem = (idx: number, patch: Partial<EditorItem>) => {
    setItems((current) => current.map((it, i) => (i === idx ? { ...it, ...patch } : it)));
  };

  const addItem = () => setItems((current) => [...current, { ...EMPTY_ITEM }]);
  const removeItem = (idx: number) =>
    setItems((current) => (current.length <= 1 ? current : current.filter((_, i) => i !== idx)));

  const handleSave = async () => {
    const trimmedName = name.trim();
    if (!trimmedName) {
      addToast('error', 'Name is required');
      return;
    }

    const payloadItems: MealTemplateItemInput[] = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const amountRaw = it.amount.trim();
      const amount = amountRaw === '' ? 0 : Number(amountRaw);
      if (amountRaw !== '' && (!Number.isFinite(amount) || Math.round(amount) !== amount)) {
        addToast('error', `Item ${i + 1}: calories must be a whole number`);
        return;
      }

      const macros: Record<string, number | null | undefined> = {};
      const keys = ['protein_g', 'carbs_g', 'fat_g', 'fiber_g', 'sugar_g'] as const;
      for (const k of keys) {
        const parsed = parseOptionalInt(it[k]);
        if (Number.isNaN(parsed)) {
          addToast('error', `Item ${i + 1}: ${k} must be a whole number`);
          return;
        }
        macros[k] = parsed === null ? undefined : parsed;
      }

      const hasContent =
        amount !== 0 ||
        it.entry_name.trim() !== '' ||
        Object.values(macros).some((v) => v != null);
      if (!hasContent) continue;

      payloadItems.push({
        entry_name: it.entry_name.trim() || null,
        amount,
        ...macros,
      });
    }

    if (payloadItems.length === 0) {
      addToast('error', 'Add at least one item with a name, calories, or macros');
      return;
    }

    setSaving(true);
    try {
      const payload = { name: trimmedName, is_favorite: isFavorite, items: payloadItems };
      if (isEdit && template) {
        await updateTemplate(template.id, payload);
        addToast('success', 'Template updated');
      } else {
        await createTemplate(payload);
        addToast('success', 'Template created');
      }
      onSaved();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save';
      addToast('error', msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open={isOpen} onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed z-50 inset-x-3 top-1/2 -translate-y-1/2 mx-auto max-w-lg max-h-[90vh] overflow-y-auto rounded-xl border-2 border-border bg-card"
          aria-describedby={undefined}
        >
          <div className="flex items-center justify-between px-4 py-3 border-b-2 border-border">
            <Dialog.Title className="text-sm font-semibold text-foreground">
              {isEdit ? 'Edit template' : 'New template'}
            </Dialog.Title>
            <Dialog.Close
              className="size-8 flex items-center justify-center rounded-md border border-destructive/30 bg-destructive/10 text-destructive hover:bg-destructive/20 cursor-pointer"
              aria-label="Close"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6L6 18" /><path d="M6 6l12 12" />
              </svg>
            </Dialog.Close>
          </div>

          <div className="flex flex-col gap-3 px-4 py-4">
            <div className="flex flex-col gap-1">
              <label htmlFor="template-name" className="text-xs font-medium text-muted-foreground">
                Name
              </label>
              <input
                id="template-name"
                type="text"
                className="rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Breakfast, post-workout, etc."
                maxLength={100}
              />
            </div>

            <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={isFavorite}
                onChange={(e) => setIsFavorite(e.target.checked)}
                className="size-4 accent-[#f59e0b]"
              />
              Show in Dashboard Quick-Add
            </label>

            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Items</span>
                <Button size="sm" variant="ghost" onClick={addItem} disabled={items.length >= 50}>
                  + Add item
                </Button>
              </div>
              {items.map((it, idx) => (
                <div
                  key={idx}
                  className="rounded-md border border-border bg-card/40 px-3 py-2 flex flex-col gap-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-muted-foreground">Item {idx + 1}</span>
                    {items.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeItem(idx)}
                        className="text-xs text-destructive hover:underline cursor-pointer"
                      >
                        Remove
                      </button>
                    )}
                  </div>
                  <input
                    type="text"
                    className="rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                    placeholder="Name (e.g. Oatmeal)"
                    value={it.entry_name}
                    maxLength={120}
                    onChange={(e) => setItem(idx, { entry_name: e.target.value })}
                  />
                  <div className="grid grid-cols-3 gap-2">
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="kcal"
                      value={it.amount}
                      onChange={(e) => setItem(idx, { amount: e.target.value })}
                    />
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="P (g)"
                      value={it.protein_g}
                      onChange={(e) => setItem(idx, { protein_g: e.target.value })}
                    />
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="C (g)"
                      value={it.carbs_g}
                      onChange={(e) => setItem(idx, { carbs_g: e.target.value })}
                    />
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="F (g)"
                      value={it.fat_g}
                      onChange={(e) => setItem(idx, { fat_g: e.target.value })}
                    />
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="Fi (g)"
                      value={it.fiber_g}
                      onChange={(e) => setItem(idx, { fiber_g: e.target.value })}
                    />
                    <input
                      type="text"
                      inputMode="tel"
                      className="rounded-md border border-input bg-background px-2 py-2 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
                      placeholder="S (g)"
                      value={it.sugar_g}
                      onChange={(e) => setItem(idx, { sugar_g: e.target.value })}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 px-4 py-3 border-t-2 border-border bg-card/60">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : isEdit ? 'Save' : 'Create'}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
