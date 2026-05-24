import { cn } from '@/lib/utils';

export type MacroPillKey = 'kcal' | 'protein' | 'carbs' | 'fat' | 'fiber' | 'sugar';

export const MACRO_PILL_STYLES: Record<MacroPillKey, { bg: string; border: string; label: string }> = {
  kcal:    { bg: 'bg-macro-kcal/10',    border: 'border-macro-kcal/20',    label: 'text-macro-kcal/70' },
  protein: { bg: 'bg-macro-protein/10', border: 'border-macro-protein/20', label: 'text-macro-protein/70' },
  carbs:   { bg: 'bg-macro-carbs/10',   border: 'border-macro-carbs/20',   label: 'text-macro-carbs/70' },
  fat:     { bg: 'bg-macro-fat/10',     border: 'border-macro-fat/20',     label: 'text-macro-fat/70' },
  fiber:   { bg: 'bg-macro-fiber/10',   border: 'border-macro-fiber/20',   label: 'text-macro-fiber/70' },
  sugar:   { bg: 'bg-macro-sugar/10',   border: 'border-macro-sugar/20',   label: 'text-macro-sugar/70' },
};

interface DisplayProps {
  macroKey: string;
  label: string;
  value: number | null;
  unit: string;
  onClick?: () => void;
  canEdit?: boolean;
}

interface EditingProps {
  macroKey: string;
  label: string;
  unit: string;
  editValue: string;
  onChange: (v: string) => void;
  onSave: () => void;
  onKeyDown: (e: React.KeyboardEvent) => void;
  inputMode?: 'tel' | 'numeric';
}

// MacroPill renders a single labeled macro chip in display mode.
// The label/value/unit triplet matches the shape used in the entries list,
// so anywhere displaying nutrient values looks consistent.
export function MacroPill({ macroKey, label, value, unit, onClick, canEdit }: DisplayProps) {
  const style = MACRO_PILL_STYLES[macroKey as MacroPillKey] ?? { bg: 'bg-white/[0.06]', border: 'border-white/[0.08]', label: 'text-muted-foreground' };
  const interactive = !!onClick && canEdit !== false;

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!interactive}
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-sm tabular-nums transition-colors',
        style.bg, style.border,
        interactive ? 'cursor-pointer hover:brightness-125' : 'cursor-default',
      )}
    >
      <span className={cn('text-[0.7rem] font-semibold uppercase tracking-wider', style.label)}>{label}</span>
      <span className="font-bold text-foreground">{value != null ? value : '-'}</span>
      {value != null && <span className="text-[0.8em] font-normal text-muted-foreground/55">{unit}</span>}
    </button>
  );
}

// MacroPillEditing renders the inline-edit input version of the pill.
// Used by anything that wants click-to-edit on a value.
export function MacroPillEditing({ macroKey, label, unit, editValue, onChange, onSave, onKeyDown, inputMode = 'numeric' }: EditingProps) {
  const style = MACRO_PILL_STYLES[macroKey as MacroPillKey] ?? { bg: 'bg-white/[0.06]', border: 'border-white/[0.08]', label: 'text-muted-foreground' };

  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-sm tabular-nums', 'border-ring', style.bg)}>
      <span className={cn('text-[0.7rem] font-semibold uppercase tracking-wider', style.label)}>{label}</span>
      <input
        className="bg-transparent border-0 outline-none text-sm font-bold text-foreground tabular-nums p-0"
        style={{ width: `${Math.max(0.5, editValue.length)}ch` }}
        value={editValue}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onSave}
        onKeyDown={onKeyDown}
        autoFocus
        inputMode={inputMode}
      />
      <span className="text-[0.8em] font-normal text-muted-foreground/55">{unit}</span>
    </span>
  );
}
