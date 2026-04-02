import { useState, useCallback, useEffect } from 'react';
import type { AIUsage } from '@/types';
import { createEntry } from '@/api/entries';
import { MACRO_LABELS, computeCaloriesFromMacros } from '@/lib/macros';
import { Button } from '@/components/ui/Button';
import { useToastStore } from '@/stores/toastStore';
import AIPhotoModal from './AIPhotoModal';
import BarcodeScanModal from './BarcodeScanModal';

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

const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring placeholder:text-muted-foreground/50';

export default function EntryForm({ selectedDate, caloriesEnabled, autoCalcCalories, enabledMacros, hasAiEnabled, aiUsage, aiProviderName, barcodeEnabled, onSubmit }: Props) {
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [macros, setMacros] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [date, setDate] = useState(selectedDate);
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [barcodeModalOpen, setBarcodeModalOpen] = useState(false);
  const [localAiUsage, setLocalAiUsage] = useState<AIUsage | null>(aiUsage);

  useEffect(() => {
    setLocalAiUsage(aiUsage);
  }, [aiUsage]);
  const addToast = useToastStore((s) => s.addToast);

  useEffect(() => {
    setDate(selectedDate);
  }, [selectedDate]);

  const safeParseMacro = (val: string | undefined): number => {
    if (!val) return 0;
    const n = parseInt(val, 10);
    return Number.isFinite(n) ? n : 0;
  };

  const computedCalories = autoCalcCalories
    ? computeCaloriesFromMacros(
        safeParseMacro(macros.protein),
        safeParseMacro(macros.carbs),
        safeParseMacro(macros.fat)
      )
    : null;

  const handleMacroChange = useCallback((key: string, value: string) => {
    setMacros((prev) => ({ ...prev, [key]: value }));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const data: Parameters<typeof createEntry>[0] = { entry_date: date };
    if (name.trim()) data.entry_name = name.trim();
    if (amount && !autoCalcCalories) {
      const parsed = Number(amount);
      if (!Number.isFinite(parsed)) {
        addToast('error', 'Invalid calorie amount');
        setLoading(false);
        return;
      }
      data.amount = parsed;
    }
    for (const key of enabledMacros) {
      if (macros[key]) {
        const parsed = Number(macros[key]);
        if (!Number.isFinite(parsed)) {
          addToast('error', `Invalid value for ${key}`);
          setLoading(false);
          return;
        }
        const macroKey = `${key}_g` as keyof typeof data;
        (data as Record<string, unknown>)[macroKey] = parsed;
      }
    }

    try {
      await createEntry(data);
      setName('');
      setAmount('');
      setMacros({});
      onSubmit();
      addToast('success', 'Entry tracked');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to track entry');
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
  const nutrientCount = (caloriesEnabled ? 1 : 0) + enabledMacros.length;
  const nutrientCols = nutrientCount <= 3 ? nutrientCount : Math.ceil(nutrientCount / 2);
  const aiDisabled = hasAiEnabled && localAiUsage && localAiUsage.remaining === 0;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">Log</h3>
      </div>
      <form onSubmit={handleSubmit} className="p-4">
        {/* Food name */}
        <div className="mb-3">
          <input
            className={inputClass}
            type="text"
            placeholder="Breakfast, snack..."
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => setName((n) => n.trim())}
            maxLength={120}
          />
        </div>

        {/* Nutrient inputs */}
        <div className="grid gap-2 mb-3" style={{ gridTemplateColumns: `repeat(${nutrientCols}, 1fr)` }}>
          {caloriesEnabled && (
            <div className="flex flex-col gap-1">
              <label className="text-xs font-semibold uppercase tracking-wider text-macro-kcal">Calories</label>
              <input
                className={`${inputClass} ${autoCalcCalories ? 'opacity-60 cursor-not-allowed' : ''}`}
                type="text"
                inputMode="tel"
                placeholder="0"
                value={autoCalcCalories ? (computedCalories ?? '') : amount}
                onChange={(e) => setAmount(e.target.value)}
                readOnly={autoCalcCalories}
              />
            </div>
          )}

          {enabledMacros.map((key) => {
            const color = {
              protein: 'text-macro-protein',
              carbs: 'text-macro-carbs',
              fat: 'text-macro-fat',
              fiber: 'text-macro-fiber',
              sugar: 'text-macro-sugar',
            }[key] || 'text-muted-foreground';

            return (
              <div key={key} className="flex flex-col gap-1">
                <label className={`text-xs font-semibold uppercase tracking-wider ${color}`}>
                  {MACRO_LABELS[key as keyof typeof MACRO_LABELS]?.label || key}
                </label>
                <input
                  className={inputClass}
                  type="text"
                  inputMode="numeric"
                  placeholder="0"
                  value={macros[key] || ''}
                  onChange={(e) => handleMacroChange(key, e.target.value)}
                />
              </div>
            );
          })}

        </div>

        {/* Date + AI + Submit */}
        <div className="flex items-center gap-2">
          <input
            type="date"
            className="rounded-md border border-input bg-muted/50 px-2 py-1.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
            value={date}
            onChange={(e) => setDate(e.target.value)}
          />

          <div className="ml-auto flex items-center gap-2">
            {barcodeEnabled && (
              <button
                type="button"
                className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-sm text-muted-foreground hover:text-foreground hover:border-primary/50 hover:bg-primary/5 transition-colors cursor-pointer bg-transparent"
                onClick={() => setBarcodeModalOpen(true)}
                title="Scan barcode"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 5v-2h4" /><path d="M17 3h4v2" /><path d="M21 19v2h-4" /><path d="M7 21h-4v-2" />
                  <path d="M7 8v8" /><path d="M12 8v8" /><path d="M17 8v8" /><path d="M5 8v8" /><path d="M15 8v8" /><path d="M19 8v8" />
                </svg>
              </button>
            )}

            <Button
              type="submit"
              size="default"
              loading={loading}
              className={
                hasInput
                  ? 'bg-primary/10 text-primary border border-primary/30 font-semibold hover:bg-primary/20 bg-gradient-to-r from-primary/15 via-secondary/15 to-primary/15 bg-[length:200%_100%] animate-[shimmer_4s_linear_infinite]'
                  : 'bg-muted text-muted-foreground border border-border hover:bg-muted hover:text-muted-foreground cursor-default'
              }
            >
              Track
            </Button>

            {hasAiEnabled && (
              <button
                type="button"
                className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-sm text-muted-foreground hover:text-foreground hover:border-primary/50 hover:bg-primary/5 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed bg-transparent"
                onClick={() => setAiModalOpen(true)}
                disabled={!!aiDisabled}
                title={aiDisabled ? 'Daily AI limit reached' : 'Estimate with AI'}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.582a.5.5 0 0 1 0 .963L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
                  <path d="M20 3v4" /><path d="M22 5h-4" />
                </svg>
                {localAiUsage && localAiUsage.limit > 0 && (
                  <span className="text-[10px] font-medium tabular-nums">{localAiUsage.remaining}</span>
                )}
              </button>
            )}
          </div>
        </div>
      </form>

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

      <BarcodeScanModal
        isOpen={barcodeModalOpen}
        onClose={() => setBarcodeModalOpen(false)}
        onResult={(result) => {
          applyResult(result);
          setBarcodeModalOpen(false);
        }}
        enabledMacros={enabledMacros}
      />
    </div>
  );
}
