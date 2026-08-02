import { useState, useCallback, useMemo } from 'react';
import type { User } from '@/types';
import { savePreferences } from '@/api/settings';
import { Card } from '@/components/ui/Card';
import { useAutosave } from '@/hooks/useAutosave';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

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
          <label htmlFor="pref-weight-unit" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Weight Unit</label>
          <Select value={weightUnit} onValueChange={(v) => setWeightUnit(v as 'kg' | 'lb')}>
            <SelectTrigger id="pref-weight-unit"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="kg">Kilograms (kg)</SelectItem>
              <SelectItem value="lb">Pounds (lb)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="pref-timezone" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Timezone</label>
          <Select value={timezone} onValueChange={setTimezone}>
            <SelectTrigger id="pref-timezone"><SelectValue /></SelectTrigger>
            <SelectContent>
              {timezones.map((tz) => <SelectItem key={tz} value={tz}>{tz}</SelectItem>)}
            </SelectContent>
          </Select>
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
