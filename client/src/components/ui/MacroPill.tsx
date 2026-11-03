import { cn } from '@/lib/utils';

export type MacroPillKey = 'kcal' | 'protein' | 'carbs' | 'fat' | 'fiber' | 'sugar';

// Labels at full colour and units at /70. The old /70 and /55 put the 10.5px
// kcal, carbs and sugar labels at 3.4-3.7:1 on the card, under WCAG AA's 4.5:1;
// /90 still fell short on the tinted editing pill and on hover. At full colour
// the weakest (kcal) is >= 4.65:1 on both card ends, tinted or hovered.
// eslint-disable-next-line react-refresh/only-export-components -- the style map is colocated with the pill by design; a full reload on HMR here is acceptable
export const MACRO_PILL_STYLES: Record<MacroPillKey, { bg: string; border: string; label: string }> = {
  kcal:    { bg: 'bg-macro-kcal/10',    border: 'border-macro-kcal/20',    label: 'text-macro-kcal' },
  protein: { bg: 'bg-macro-protein/10', border: 'border-macro-protein/20', label: 'text-macro-protein' },
  carbs:   { bg: 'bg-macro-carbs/10',   border: 'border-macro-carbs/20',   label: 'text-macro-carbs' },
  fat:     { bg: 'bg-macro-fat/10',     border: 'border-macro-fat/20',     label: 'text-macro-fat' },
  fiber:   { bg: 'bg-macro-fiber/10',   border: 'border-macro-fiber/20',   label: 'text-macro-fiber' },
  sugar:   { bg: 'bg-macro-sugar/10',   border: 'border-macro-sugar/20',   label: 'text-macro-sugar' },
};

interface DisplayProps {
  macroKey: string;
  label: string;
  value: number | null;
  unit: string;
  onClick?: () => void;
  canEdit?: boolean;
  /** Marks the pill so its row can return focus to it after an inline edit. */
  editField?: string;
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
  /** Marks the value invalid; `describedBy` is the id of the message saying why. */
  invalid?: boolean;
  describedBy?: string;
  'aria-label'?: string;
}

// MacroPill renders a single labeled macro chip in display mode.
// The label/value/unit triplet matches the shape used in the entries list,
// so anywhere displaying nutrient values looks consistent.
export function MacroPill({ macroKey, label, value, unit, onClick, canEdit, editField }: DisplayProps) {
  const style = MACRO_PILL_STYLES[macroKey as MacroPillKey] ?? { bg: 'bg-white/[0.06]', border: 'border-white/[0.08]', label: 'text-muted-foreground' };
  const interactive = !!onClick && canEdit !== false;

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!interactive}
      data-edit-field={editField}
      className={cn(
        'inline-flex min-h-6 items-center gap-1 rounded-md border border-transparent px-1.5 py-0.5 text-sm tabular-nums transition-colors',
        interactive ? 'cursor-pointer hover:bg-white/[0.06]' : 'cursor-default',
      )}
    >
      <span className={cn('text-[0.7rem] font-semibold uppercase tracking-wider', style.label)}>{label}</span>
      <span className="font-bold text-foreground">{value != null ? value : '-'}</span>
      {value != null && <span className="text-[0.8em] font-normal text-muted-foreground/70">{unit}</span>}
    </button>
  );
}

// MacroPillEditing renders the inline-edit input version of the pill.
// Used by anything that wants click-to-edit on a value.
// inputMode defaults to "tel": the "numeric" keypad has no comma, dot or
// operators, so neither a decimal ("12,5") nor an expression could be typed.
export function MacroPillEditing({ macroKey, label, unit, editValue, onChange, onSave, onKeyDown, inputMode = 'tel', invalid = false, describedBy, 'aria-label': ariaLabel }: EditingProps) {
  const style = MACRO_PILL_STYLES[macroKey as MacroPillKey] ?? { bg: 'bg-white/[0.06]', border: 'border-white/[0.08]', label: 'text-muted-foreground' };

  return (
    // Same box as MacroPill (radius, padding, min-height, 1px border) so entering
    // edit mode only lights up the border instead of growing a bigger pill that
    // pushes the neighbouring pills sideways and the row down.
    <span className={cn('inline-flex min-h-6 items-center gap-1 rounded-md border px-1.5 py-0.5 text-sm tabular-nums', invalid ? 'border-destructive' : 'border-ring', style.bg)}>
      <span className={cn('text-[0.7rem] font-semibold uppercase tracking-wider', style.label)}>{label}</span>
      <input
        className="bg-transparent border-0 outline-none p-0 font-bold text-foreground"
        style={{ width: `${Math.max(0.5, editValue.length)}ch` }}
        value={editValue}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onSave}
        onKeyDown={onKeyDown}
        autoFocus
        inputMode={inputMode}
        aria-invalid={invalid || undefined}
        aria-describedby={invalid ? describedBy : undefined}
        aria-label={ariaLabel}
      />
      <span className="text-[0.8em] font-normal text-muted-foreground/70">{unit}</span>
    </span>
  );
}
