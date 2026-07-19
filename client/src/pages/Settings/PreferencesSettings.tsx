import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { User } from '@/types';
import { savePreferences } from '@/api/settings';
import { Card } from '@/components/ui/Card';
import { useAutosave } from '@/hooks/useAutosave';
import i18n, { SUPPORTED_LANGUAGES } from '@/i18n';

const selectClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  user: User;
  timezones: string[];
  onSave: () => void;
}

export default function PreferencesSettings({ user, timezones, onSave }: Props) {
  const { t } = useTranslation('settings');
  const [timezone, setTimezone] = useState(user.timezone);
  const [weightUnit, setWeightUnit] = useState(user.weightUnit);
  // '' = Automatic (browser language); a code = explicit override.
  const [language, setLanguage] = useState<string>(user.language ?? '');

  const data = useMemo(() => ({ timezone, weightUnit, language }), [timezone, weightUnit, language]);

  const saveFn = useCallback(async (d: typeof data) => {
    await savePreferences({ weight_unit: d.weightUnit, timezone: d.timezone, language: d.language });
    onSave();
  }, [onSave]);

  const { status } = useAutosave(data, saveFn);

  const onLanguageChange = (code: string) => {
    setLanguage(code);
    if (code === '') {
      localStorage.removeItem('i18nextLng'); // let the browser decide again
      const detected = (navigator.language || 'en').split('-')[0];
      i18n.changeLanguage(detected);
    } else {
      i18n.changeLanguage(code);
    }
  };

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">{t('preferences.heading')}</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="pref-language" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('i18n.language')}</label>
          <select id="pref-language" value={language} onChange={(e) => onLanguageChange(e.target.value)} className={selectClass}>
            <option value="">{t('i18n.automatic')}</option>
            {SUPPORTED_LANGUAGES.map((l) => <option key={l.code} value={l.code}>{l.endonym}</option>)}
          </select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="pref-weight-unit" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('preferences.weightUnit.label')}</label>
          <select id="pref-weight-unit" value={weightUnit} onChange={(e) => setWeightUnit(e.target.value as 'kg' | 'lb')} className={selectClass}>
            <option value="kg">{t('preferences.weightUnit.kg')}</option>
            <option value="lb">{t('preferences.weightUnit.lb')}</option>
          </select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="pref-timezone" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('preferences.timezone.label')}</label>
          <select id="pref-timezone" value={timezone} onChange={(e) => setTimezone(e.target.value)} className={selectClass}>
            {timezones.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
        </div>
      </div>
      {(status === 'saving' || status === 'saved') && (
        <div className="flex justify-end mt-2">
          {status === 'saving' && <span className="text-xs text-muted-foreground animate-pulse">{t('status.saving')}</span>}
          {status === 'saved' && <span className="text-xs text-green-400">{t('status.saved')}</span>}
        </div>
      )}
    </Card>
  );
}
