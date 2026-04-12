import { useState, useCallback, useMemo } from 'react';
import type { User } from '@/types';
import { savePreferences } from '@/api/settings';
import { Card } from '@/components/ui/Card';
import { useAutosave } from '@/hooks/useAutosave';

const selectClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  user: User;
  timezones: string[];
  onSave: () => void;
}

export default function PreferencesSettings({ user, timezones, onSave }: Props) {
  const [timezone, setTimezone] = useState(user.timezone);
  const [weightUnit, setWeightUnit] = useState(user.weightUnit);

  const data = useMemo(() => ({ timezone, weightUnit }), [timezone, weightUnit]);

  const saveFn = useCallback(async (d: typeof data) => {
    await savePreferences({ weight_unit: d.weightUnit, timezone: d.timezone });
    onSave();
  }, [onSave]);

  const { status } = useAutosave(data, saveFn);

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">Internationalization</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Weight Unit</label>
          <select value={weightUnit} onChange={(e) => setWeightUnit(e.target.value as 'kg' | 'lb')} className={selectClass}>
            <option value="kg">Kilograms (kg)</option>
            <option value="lb">Pounds (lb)</option>
          </select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Timezone</label>
          <select value={timezone} onChange={(e) => setTimezone(e.target.value)} className={selectClass}>
            {timezones.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
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
