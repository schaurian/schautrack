import { useState, useCallback, useEffect, useRef, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient } from '@tanstack/react-query';
import type { AIUsage } from '@/types';
import { createEntry } from '@/api/entries';
import { createSavedFood } from '@/api/savedFoods';
import { MACRO_LABELS, computeCaloriesFromMacros } from '@/lib/macros';
import { MAX_ENTRY_CALORIES, MAX_ENTRY_MACRO, expressionPreview, validateEntryField, type FieldResult } from '@/lib/entryValidation';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { QuantityStepper } from '@/components/ui/QuantityStepper';
import { useToastStore } from '@/stores/toastStore';
import { lazyRoute } from '@/lib/lazyRoute';

// Lazy-loaded so their chunks (BarcodeScanModal pulls in the heavy quagga2
// barcode decoder) are only fetched when a user first opens a scanner, rather
// than eagerly on every page load.
const AIPhotoModal = lazyRoute(() => import('./AIPhotoModal'));
const BarcodeScanModal = lazyRoute(() => import('./BarcodeScanModal'));

interface Props {
  selectedDate: string;
  caloriesEnabled: boolean;
  autoCalcCalories: boolean;
  enabledMacros: string[];
  hasAiEnabled: boolean;
  aiUsage: AIUsage | null;
  aiProviderName: string | null;
  barcodeEnabled: boolean;
  onSubmit: () => void;
}

// A server rejection names the field only in its message. Mapped to the field
// the message is about so a mismatch with the client-side rules still lands
// inline; anything else stays a toast.
const SERVER_CALORIES_RANGE = /^Calories must be between/;
const SERVER_MACRO_RANGE = /^Macro values must be between/;

const inputBase = 'w-full rounded-md border bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:ring-1 placeholder:text-muted-foreground/50';
const inputClass = `${inputBase} border-input focus:border-ring focus:ring-ring`;
// Swapped in rather than layered on: two border colours in one class list
// resolve by stylesheet order, not by which was written last.
const invalidInputClass = `${inputBase} border-destructive focus:border-destructive focus:ring-destructive`;

// Secondary entry methods (photo, barcode) and save-as-quick-add. Same
// vocabulary as .surface — hairline edge plus a 1px inner top highlight —
// at tile scale, so they read as part of the card rather than as leftover
// bordered boxes next to the primary action.
const actionTileClass =
  'grid size-10 shrink-0 place-items-center rounded-xl bg-white/[0.04] text-muted-foreground cursor-pointer ' +
  'shadow-[0_0_0_1px_rgba(255,255,255,0.07),inset_0_1px_0_rgba(255,255,255,0.06)] ' +
  'transition-colors hover:bg-white/[0.07] hover:text-foreground ' +
  'disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-white/[0.04] disabled:hover:text-muted-foreground';

export default function EntryForm({ selectedDate, caloriesEnabled, autoCalcCalories, enabledMacros, hasAiEnabled, aiUsage, aiProviderName, barcodeEnabled, onSubmit }: Props) {
  const { t } = useTranslation('dashboard');
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [macros, setMacros] = useState<Record<string, string>>({});
  const [quantity, setQuantity] = useState(1);
  const [loading, setLoading] = useState(false);
  const [date, setDate] = useState(selectedDate);
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [barcodeModalOpen, setBarcodeModalOpen] = useState(false);
  const [savingFood, setSavingFood] = useState(false);
  const [localAiUsage, setLocalAiUsage] = useState<AIUsage | null>(aiUsage);
  const [errors, setErrors] = useState<Record<string, FieldResult & { ok: false }>>({});
  const fieldRefs = useRef<Record<string, HTMLInputElement | null>>({});
  const queryClient = useQueryClient();

  // Once a modal has been opened it stays mounted (kept alive by these latches)
  // so its existing close-cleanup effects keep running; it just isn't mounted —
  // and its chunk isn't fetched — until the first open.
  const aiModalMounted = useRef(false);
  const barcodeModalMounted = useRef(false);
  if (aiModalOpen) aiModalMounted.current = true;
  if (barcodeModalOpen) barcodeModalMounted.current = true;

  useEffect(() => {
    setLocalAiUsage(aiUsage);
  }, [aiUsage]);
  const addToast = useToastStore((s) => s.addToast);

  useEffect(() => {
    setDate(selectedDate);
  }, [selectedDate]);

  // Same evaluation the submit uses, so "2*15" protein feeds 30 g into the
  // auto-calculated calories rather than parseInt's 2.
  const safeParseMacro = (val: string | undefined): number => {
    const r = validateEntryField('macro', val);
    return r.ok && r.value !== null ? r.value : 0;
  };

  const computedCalories = autoCalcCalories
    ? computeCaloriesFromMacros(
        safeParseMacro(macros.protein),
        safeParseMacro(macros.carbs),
        safeParseMacro(macros.fat)
      )
    : null;

  const clearError = useCallback((field: string) => {
    setErrors((prev) => {
      if (!(field in prev)) return prev;
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }, []);

  const handleMacroChange = useCallback((key: string, value: string) => {
    setMacros((prev) => ({ ...prev, [key]: value }));
    clearError(key);
  }, [clearError]);

  // Field order matches the DOM, so the first entry is the field to focus.
  const fieldOrder = [...(caloriesEnabled && !autoCalcCalories ? ['calories'] : []), ...enabledMacros];

  const showErrors = (next: Record<string, FieldResult & { ok: false }>) => {
    setErrors(next);
    const first = fieldOrder.find((f) => f in next);
    if (first) fieldRefs.current[first]?.focus();
  };

  // The "= 300" preview under an expression, and the inline error once a submit
  // has found the field invalid. Both are wired to the input via
  // aria-describedby so a screen reader reads them with the field.
  const fieldProps = (field: string, inputId: string, raw: string | undefined) => {
    const err = errors[field];
    const preview = err ? null : expressionPreview(raw);
    const errorId = `${inputId}-error`;
    const previewId = `${inputId}-preview`;
    return {
      inputProps: {
        id: inputId,
        ref: (el: HTMLInputElement | null) => { fieldRefs.current[field] = el; },
        'aria-invalid': err ? true : undefined,
        'aria-describedby': err ? errorId : preview !== null ? previewId : undefined,
      },
      inputClass: err ? invalidInputClass : inputClass,
      messages: (
        <>
          {preview !== null && (
            <span id={previewId} data-testid={`${inputId}-preview`} className="text-xs tabular-nums text-muted-foreground">
              = {preview}
            </span>
          )}
          {err && (
            <span id={errorId} className="text-xs text-destructive">
              {errorText(err, Math.max(1, Math.trunc(quantity)))}
            </span>
          )}
        </>
      ),
    };
  };

  const errorText = (err: FieldResult & { ok: false }, qty: number) => {
    if (err.error === 'invalid') return t('entries.fieldInvalid');
    return qty > 1
      ? t('entries.fieldRangeQty', { min: err.min, max: err.max, qty })
      : t('entries.fieldRange', { min: err.min, max: err.max });
  };

  const handleSubmit = async (e: React.SubmitEvent) => {
    e.preventDefault();

    const qty = Math.max(1, Math.trunc(quantity));
    const data: Parameters<typeof createEntry>[0] = { entry_date: date };
    if (name.trim()) data.entry_name = name.trim();
    const found: Record<string, FieldResult & { ok: false }> = {};
    if (amount && !autoCalcCalories) {
      const r = validateEntryField('calories', amount, qty);
      if (!r.ok) found.calories = r;
      else if (r.value !== null) data.amount = r.value * qty;
    }
    for (const key of enabledMacros) {
      const r = validateEntryField('macro', macros[key], qty);
      if (!r.ok) found[key] = r;
      else if (r.value !== null) (data as Record<string, unknown>)[`${key}_g`] = r.value * qty;
    }
    if (Object.keys(found).length > 0) {
      showErrors(found);
      return;
    }
    setErrors({});
    setLoading(true);

    try {
      await createEntry(data);
      setName('');
      setAmount('');
      setMacros({});
      setQuantity(1);
      onSubmit();
      addToast('success', t('entries.toastTracked'));
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : '';
      const range = (field: string): FieldResult & { ok: false } => {
        const isCal = field === 'calories';
        return { ok: false, error: 'range', min: isCal ? -MAX_ENTRY_CALORIES : 0, max: isCal ? MAX_ENTRY_CALORIES : MAX_ENTRY_MACRO };
      };
      if (SERVER_CALORIES_RANGE.test(msg) && fieldOrder.includes('calories')) {
        showErrors({ calories: range('calories') });
      } else if (SERVER_MACRO_RANGE.test(msg) && enabledMacros.some((k) => macros[k])) {
        showErrors(Object.fromEntries(enabledMacros.filter((k) => macros[k]).map((k) => [k, range(k)])));
      } else {
        addToast('error', err instanceof Error ? err.message : t('entries.toastTrackFailed'));
      }
    }
    setLoading(false);
  };

  const applyResult = (result: { name?: string; calories?: number; macros?: Record<string, number> }) => {
    if (result.name) setName(result.name);
    if (result.calories) setAmount(String(result.calories));
    if (result.macros) {
      const newMacros: Record<string, string> = {};
      for (const [key, val] of Object.entries(result.macros)) {
        if (enabledMacros.includes(key) && val) {
          newMacros[key] = String(val);
        }
      }
      setMacros(newMacros);
    }
  };

  const hasInput = !!(amount || computedCalories || Object.values(macros).some((v) => v));
  const canSaveAsFood = !!(name.trim() && hasInput);
  const aiDisabled = hasAiEnabled && localAiUsage && localAiUsage.limit > 0 && localAiUsage.remaining === 0;

  const showQtyPreview = quantity > 1 && enabledMacros.some((k) => macros[k]);

  const handleSaveAsFood = async () => {
    if (!canSaveAsFood || savingFood) return;
    setSavingFood(true);
    try {
      const payload: Parameters<typeof createSavedFood>[0] = { name: name.trim() };
      if (amount && !autoCalcCalories) {
        const r = validateEntryField('calories', amount);
        if (r.ok && r.value !== null) payload.amount = r.value;
      } else if (computedCalories) {
        payload.amount = computedCalories;
      }
      for (const key of enabledMacros) {
        const r = validateEntryField('macro', macros[key]);
        if (r.ok && r.value !== null) {
          (payload as Record<string, unknown>)[`${key}_g`] = r.value;
        }
      }
      await createSavedFood(payload);
      queryClient.invalidateQueries({ queryKey: ['savedFoods'] });
      addToast('success', t('entries.toastSavedFood', { name: name.trim() }));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('entries.toastSaveFoodFailed'));
    }
    setSavingFood(false);
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="flex flex-col pt-1">
        {/* Food name + Quantity */}
        <div className="mb-3 flex items-end gap-2">
          <div className="flex flex-1 flex-col">
            <input
              className={inputClass}
              type="text"
              aria-label={t('entries.foodNameAriaLabel')}
              placeholder={t('entries.foodNamePlaceholder')}
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setName((n) => n.trim())}
              maxLength={120}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{t('entries.qtyLabel')}</label>
            <QuantityStepper value={quantity} onChange={setQuantity} />
          </div>
        </div>

        {/* Calories */}
        {caloriesEnabled && (() => {
          const f = fieldProps('calories', 'entry-calories', autoCalcCalories ? undefined : amount);
          return (
            <div className="mb-3 flex flex-col gap-1">
              <label htmlFor="entry-calories" className="text-xs font-semibold uppercase tracking-wider text-macro-kcal">{t('entries.caloriesLabel')}</label>
              <input
                {...f.inputProps}
                className={`${f.inputClass} ${autoCalcCalories ? 'opacity-60 cursor-not-allowed' : ''}`}
                type="text"
                inputMode="tel"
                placeholder="0"
                value={autoCalcCalories ? (computedCalories ?? '') : amount}
                onChange={(e) => { setAmount(e.target.value); clearError('calories'); }}
                readOnly={autoCalcCalories}
              />
              {f.messages}
            </div>
          );
        })()}

        {/* Macros grid */}
        {enabledMacros.length > 0 && (
          <div
            className="grid gap-2 mb-3"
            style={{ gridTemplateColumns: `repeat(${enabledMacros.length <= 3 ? enabledMacros.length : Math.ceil(enabledMacros.length / 2)}, 1fr)` }}
          >
            {enabledMacros.map((key) => {
              const color = {
                protein: 'text-macro-protein',
                carbs: 'text-macro-carbs',
                fat: 'text-macro-fat',
                fiber: 'text-macro-fiber',
                sugar: 'text-macro-sugar',
              }[key] || 'text-muted-foreground';

              const f = fieldProps(key, `entry-macro-${key}`, macros[key]);

              return (
                <div key={key} className="flex flex-col gap-1">
                  <label htmlFor={`entry-macro-${key}`} className={`text-xs font-semibold uppercase tracking-wider ${color}`}>
                    {MACRO_LABELS[key as keyof typeof MACRO_LABELS]?.label || key}
                  </label>
                  <input
                    {...f.inputProps}
                    className={f.inputClass}
                    type="text"
                    inputMode="numeric"
                    placeholder="0"
                    value={macros[key] || ''}
                    onChange={(e) => handleMacroChange(key, e.target.value)}
                  />
                  {f.messages}
                </div>
              );
            })}
          </div>
        )}

        {/* Multiplier preview */}
        {showQtyPreview && (
          <div className="mb-3 text-xs text-muted-foreground tabular-nums">
            {t('entries.qtyMacrosPreview', { count: quantity })}
          </div>
        )}

        {/* Date + AI + Submit */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <input
            type="date"
            aria-label={t('entries.entryDateAriaLabel')}
            className="rounded-md border border-input bg-muted/50 px-2 py-1.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
            value={date}
            onChange={(e) => setDate(e.target.value)}
          />

          <div className="flex items-center gap-2 sm:ml-auto">
            {hasAiEnabled && (
              <button
                type="button"
                className={`relative ${actionTileClass}`}
                onClick={() => setAiModalOpen(true)}
                disabled={!!aiDisabled}
                aria-label={t('entries.estimateAiAriaLabel')}
                title={aiDisabled ? t('entries.aiLimitReachedTitle') : t('entries.estimateAiTitle')}
              >
                <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.582a.5.5 0 0 1 0 .963L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
                  <path d="M20 3v4" /><path d="M22 5h-4" />
                </svg>
                {localAiUsage && localAiUsage.limit > 0 && (
                  <span className="absolute -bottom-0.5 -right-0.5 rounded-full bg-background px-1 text-[10px] font-semibold tabular-nums leading-tight text-muted-foreground">
                    {localAiUsage.remaining}
                  </span>
                )}
              </button>
            )}

            {barcodeEnabled && (
              <button
                type="button"
                className={actionTileClass}
                onClick={() => setBarcodeModalOpen(true)}
                aria-label={t('entries.scanBarcodeLabel')}
                title={t('entries.scanBarcodeLabel')}
              >
                <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 5v-2h4" /><path d="M17 3h4v2" /><path d="M21 19v2h-4" /><path d="M7 21h-4v-2" />
                  <path d="M7 8v8" /><path d="M12 8v8" /><path d="M17 8v8" /><path d="M5 8v8" /><path d="M15 8v8" /><path d="M19 8v8" />
                </svg>
              </button>
            )}

            <button
              type="button"
              className={actionTileClass}
              onClick={handleSaveAsFood}
              disabled={!canSaveAsFood || savingFood}
              aria-label={t('entries.saveAsQuickAddLabel')}
              title={canSaveAsFood ? t('entries.saveAsTemplateTitle') : t('entries.addNameAndValuesFirstTitle')}
            >
              {savingFood ? (
                <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
                </svg>
              )}
            </button>

            <Button
              type="submit"
              size="default"
              loading={loading}
              disabled={!hasInput}
              className={`flex-1 sm:flex-initial border-0 font-semibold ${
                hasInput
                  ? 'bg-gradient-to-br from-secondary to-primary text-primary-foreground shadow-[0_4px_16px_rgba(109,140,255,0.35)] hover:brightness-110'
                  : 'bg-white/[0.04] text-muted-foreground shadow-[inset_0_0_0_1px_rgba(255,255,255,0.07)]'
              }`}
            >
              {t('entries.trackButton')}
            </Button>
          </div>
        </div>
      </form>

      {aiModalMounted.current && (
        <Suspense fallback={null}>
          <AIPhotoModal
            isOpen={aiModalOpen}
            onClose={() => setAiModalOpen(false)}
            onResult={(result) => {
              applyResult(result);
              setLocalAiUsage((u) => u && u.limit > 0 ? { ...u, used: u.used + 1, remaining: Math.max(0, u.remaining - 1) } : u);
              setAiModalOpen(false);
            }}
            enabledMacros={enabledMacros}
            providerName={aiProviderName}
          />
        </Suspense>
      )}

      {barcodeModalMounted.current && (
        <Suspense fallback={null}>
          <BarcodeScanModal
            isOpen={barcodeModalOpen}
            onClose={() => setBarcodeModalOpen(false)}
            onResult={(result) => {
              applyResult(result);
              setBarcodeModalOpen(false);
            }}
            enabledMacros={enabledMacros}
          />
        </Suspense>
      )}
    </>
  );
}
