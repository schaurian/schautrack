import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { User } from '@/types';
import { saveAiSettings } from '@/api/settings';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { useToastStore } from '@/stores/toastStore';
import { useAutosave } from '@/hooks/useAutosave';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

/** Radix Select disallows an item with value="" — map this sentinel back to ''. */
const NONE = '__none__';

interface Props {
  user: User;
  onSave: () => void;
}

export default function AISettings({ user, onSave }: Props) {
  const { t } = useTranslation('settings');
  const [provider, setProvider] = useState(user.preferredAiProvider || '');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState(user.aiModel || '');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  // Auto-save provider/model only. The API key is deliberately excluded:
  // debounced saves while typing would store partial keys on the server.
  const autoData = useMemo(() => ({ provider, model }), [provider, model]);

  const autoSaveFn = useCallback(async (d: typeof autoData) => {
    await saveAiSettings({ ai_provider: d.provider, ai_model: d.model });
    onSave();
  }, [onSave]);

  const { status } = useAutosave(autoData, autoSaveFn, { delay: 1200 });

  // The key is submitted explicitly on blur of its input, and the field is
  // only cleared after that save succeeds.
  const [keySaving, setKeySaving] = useState(false);
  const handleKeyBlur = async () => {
    const key = apiKey.trim();
    if (!key) return;
    setKeySaving(true);
    try {
      // The server overwrites provider/model on every save, so send the
      // current values alongside the key.
      await saveAiSettings({ ai_provider: provider, ai_key: key, ai_model: model });
      setApiKey('');
      onSave();
      addToast('success', t('ai.keySaved'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('ai.keySaveFailed'));
    }
    setKeySaving(false);
  };

  const handleClear = async () => {
    setLoading(true);
    try {
      await saveAiSettings({ clear_settings: 'true' });
      setProvider(''); setModel(''); setApiKey('');
      onSave();
      addToast('success', t('ai.settingsCleared'));
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('ai.clearFailed'));
    }
    setLoading(false);
  };

  return (
    <Card data-testid="ai-settings-card">
      <h3 className="text-sm font-semibold mb-3">{t('ai.heading')}</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('ai.provider')}</label>
          <Select value={provider || NONE} onValueChange={(v) => setProvider(v === NONE ? '' : v)}>
            <SelectTrigger data-testid="ai-provider"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>{t('ai.providerDefault')}</SelectItem>
              <SelectItem value="openai">OpenAI</SelectItem>
              <SelectItem value="claude">Claude</SelectItem>
              <SelectItem value="ollama">Ollama</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Input label={t('ai.modelLabel')} value={model} onChange={(e) => setModel(e.target.value)} placeholder={t('ai.modelPlaceholder')} />
        <Input label={t('ai.apiKeyLabel')} type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
          onBlur={handleKeyBlur} disabled={keySaving}
          placeholder={user.hasAiKey ? t('ai.apiKeyMaskedPlaceholder', { last4: user.aiKeyLast4 }) : t('ai.apiKeyPlaceholder')} />
        {!user.hasAiKey && user.hasGlobalAiKey && (
          <p className="text-xs text-muted-foreground">{t('ai.globalKeyNotice')}</p>
        )}
      </div>
      <div className="border-t border-border pt-3 mt-3 flex flex-col gap-2">
        {status === 'saving' && <span className="text-xs text-muted-foreground animate-pulse text-right">{t('status.saving')}</span>}
        {status === 'saved' && <span className="text-xs text-green-400 text-right">{t('status.saved')}</span>}
        <Button type="button" variant="destructive" className="w-full" onClick={handleClear} loading={loading}>{t('ai.clearAll')}</Button>
      </div>
    </Card>
  );
}
