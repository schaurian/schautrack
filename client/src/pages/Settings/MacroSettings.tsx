import { useState, useCallback, useMemo } from 'react';
import type { User } from '@/types';
import { saveMacros } from '@/api/settings';
import { MACRO_LABELS } from '@/lib/macros';
import { Card } from '@/components/ui/Card';
import { cn } from '@/lib/utils';
import { useAutosave } from '@/hooks/useAutosave';

const MACRO_KEYS = ['protein', 'carbs', 'fat', 'fiber', 'sugar'];

const inputClass = 'w-24 rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';
const selectClass = 'rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

const MACRO_STYLES: Record<string, { label: string; border: string; bg: string }> = {
  calories: { label: 'text-macro-kcal', border: 'border-l-macro-kcal', bg: 'bg-macro-kcal/[0.04]' },
  protein:  { label: 'text-macro-protein', border: 'border-l-macro-protein', bg: 'bg-macro-protein/[0.04]' },
  carbs:    { label: 'text-macro-carbs', border: 'border-l-macro-carbs', bg: 'bg-macro-carbs/[0.04]' },
  fat:      { label: 'text-macro-fat', border: 'border-l-macro-fat', bg: 'bg-macro-fat/[0.04]' },
  fiber:    { label: 'text-macro-fiber', border: 'border-l-macro-fiber', bg: 'bg-macro-fiber/[0.04]' },
  sugar:    { label: 'text-macro-sugar', border: 'border-l-macro-sugar', bg: 'bg-macro-sugar/[0.04]' },
};

interface Props {
  user: User;
  onSave: () => void;
}

export default function MacroSettings({ user, onSave }: Props) {
  const macrosEnabled = user.macrosEnabled || {};
  const macroGoals = user.macroGoals || {};

  const [enabled, setEnabled] = useState<Record<string, boolean>>({
    calories: macrosEnabled.calories !== false,
    ...Object.fromEntries(MACRO_KEYS.map((k) => [k, macrosEnabled[k] === true])),
    auto_calc_calories: macrosEnabled.auto_calc_calories === true,
  });
  const [goals, setGoals] = useState<Record<string, string>>({
    calories: macroGoals.calories != null ? String(macroGoals.calories) : '',
    ...Object.fromEntries(MACRO_KEYS.map((k) => [k, macroGoals[k] != null ? String(macroGoals[k]) : ''])),
  });
  const [modes, setModes] = useState<Record<string, string>>({
    calories: String(macroGoals.calories_mode || 'limit'),
    ...Object.fromEntries(MACRO_KEYS.map((k) => [k, macroGoals[`${k}_mode`] || ''])),
  });
  const [threshold, setThreshold] = useState(String(user.goalThreshold ?? 10));

  const canAutoCalc = enabled.calories && enabled.protein && enabled.carbs && enabled.fat;

  // Build the save payload from current state
  const data = useMemo(() => ({ enabled, goals, modes, threshold, canAutoCalc }), [enabled, goals, modes, threshold, canAutoCalc]);

  const saveFn = useCallback(async (d: typeof data) => {
    const payload: Record<string, string | boolean | number> = {
      calorie_goal: d.goals.calories || '0',
      calories_enabled: d.enabled.calories ? 'on' : '',
      calories_mode: d.modes.calories,
      auto_calc_calories: d.enabled.auto_calc_calories && d.canAutoCalc ? 'on' : '',
      goal_threshold: d.threshold,
    };
    for (const key of MACRO_KEYS) {
      payload[`${key}_enabled`] = d.enabled[key] ? 'on' : '';
      payload[`${key}_goal`] = d.goals[key] || '0';
      if (d.modes[key]) payload[`${key}_mode`] = d.modes[key];
    }
    await saveMacros(payload);
    onSave();
  }, [onSave]);

  const { status } = useAutosave(data, saveFn, { delay: 1000 });

  const allKeys = ['calories', ...MACRO_KEYS];

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">Nutrition Goals</h3>
      <div className="flex flex-col gap-px">
        {allKeys.map((key) => {
          const label = key === 'calories' ? 'Calories' : (MACRO_LABELS[key as keyof typeof MACRO_LABELS]?.label || key);
          const unit = key === 'calories' ? 'kcal' : 'g';
          const isChecked = enabled[key] || false;
          const style = MACRO_STYLES[key];

          return (
            <div
              key={key}
              className={cn(
                'flex items-center gap-3 border-l-3 rounded-r-lg px-3 py-2.5 transition-opacity',
                style?.border,
                isChecked ? style?.bg : 'bg-transparent opacity-50',
              )}
            >
              <label className="flex items-center gap-2.5 cursor-pointer min-w-[110px] shrink-0">
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={(e) => setEnabled({ ...enabled, [key]: e.target.checked })}
                />
                <span className={cn('text-sm font-medium', style?.label)}>{label}</span>
              </label>
              <div className={cn('flex items-center gap-2 ml-auto', !isChecked && 'pointer-events-none')}>
                <span className="relative flex items-center">
                  <input
                    className={`${inputClass} pr-9`}
                    type="number"
                    value={goals[key]}
                    onChange={(e) => setGoals({ ...goals, [key]: e.target.value })}
                    placeholder="Goal"
                    tabIndex={isChecked ? 0 : -1}
                  />
                  <span className={cn('absolute right-2.5 text-[10px] tracking-wide opacity-60 pointer-events-none', style?.label)}>{unit}</span>
                </span>
                <select
                  className={selectClass}
                  value={modes[key]}
                  onChange={(e) => setModes({ ...modes, [key]: e.target.value })}
                  tabIndex={isChecked ? 0 : -1}
                >
                  <option value="limit">Limit</option>
                  <option value="target">Target</option>
                </select>
              </div>
            </div>
          );
        })}

        {canAutoCalc && (
          <div className="flex items-center gap-3 border-l-3 border-l-primary/40 rounded-r-lg px-3 py-2.5 bg-primary/[0.04]">
            <label className="flex items-center gap-2.5 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={enabled.auto_calc_calories}
                onChange={(e) => setEnabled({ ...enabled, auto_calc_calories: e.target.checked })}
              />
              <span className="text-primary font-medium">Auto-calculate calories</span>
            </label>
            <span className="text-xs text-muted-foreground ml-auto">P×4 + C×4 + F×9</span>
          </div>
        )}

        <div className="flex items-center gap-3 border-l-3 border-l-warning/40 rounded-r-lg px-3 py-2.5 bg-warning/[0.04] mt-px">
          <div className="flex items-center gap-2.5 min-w-[110px] shrink-0">
            <div className="size-4 shrink-0" />
            <span className="text-sm font-medium text-warning">Threshold</span>
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <span className="relative flex items-center">
              <input className={`${inputClass} pr-9`} type="number" min="0" max="99" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
              <span className="absolute right-2.5 text-[10px] tracking-wide text-warning opacity-60 pointer-events-none">%</span>
            </span>
            <select className={selectClass} tabIndex={-1} aria-hidden="true" style={{ opacity: 0, pointerEvents: 'none' }}>
              <option value="limit">Limit</option>
              <option value="target">Target</option>
            </select>
          </div>
        </div>
      </div>
      {(status === 'saving' || status === 'saved') && (
        <div className="flex justify-end mt-2">
          {status === 'saving' && <span className="text-xs text-muted-foreground animate-pulse">Saving...</span>}
          {status === 'saved' && <span className="text-xs text-green-400">Saved</span>}
        </div>
      )}
    </Card>
  );
}
