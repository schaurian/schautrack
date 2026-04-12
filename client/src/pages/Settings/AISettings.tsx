import { useState, useCallback, useMemo } from 'react';
import type { User } from '@/types';
import { saveAiSettings } from '@/api/settings';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { useToastStore } from '@/stores/toastStore';
import { useAutosave } from '@/hooks/useAutosave';

const selectClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  user: User;
  onSave: () => void;
}

export default function AISettings({ user, onSave }: Props) {
  const [provider, setProvider] = useState(user.preferredAiProvider || '');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState(user.aiModel || '');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  // Auto-save everything including API key (on blur via useAutosave)
  const autoData = useMemo(() => ({ provider, model, apiKey }), [provider, model, apiKey]);

  const autoSaveFn = useCallback(async (d: typeof autoData) => {
    await saveAiSettings({ ai_provider: d.provider, ai_key: d.apiKey, ai_model: d.model });
    if (d.apiKey) setApiKey('');
    onSave();
  }, [onSave]);

  const { status } = useAutosave(autoData, autoSaveFn, { delay: 1200 });

  const handleClear = async () => {
    setLoading(true);
    try {
      await saveAiSettings({ clear_settings: 'true' });
      setProvider(''); setModel(''); setApiKey('');
      onSave();
      addToast('success', 'AI settings cleared');
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to clear AI settings');
    }
    setLoading(false);
  };

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-3">AI Settings</h3>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Provider</label>
          <select value={provider} onChange={(e) => setProvider(e.target.value)} className={selectClass}>
            <option value="">Default</option>
            <option value="openai">OpenAI</option>
            <option value="claude">Claude</option>
            <option value="ollama">Ollama</option>
          </select>
        </div>
        <Input label="Model (optional)" value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. gpt-4o" />
        <Input label="API Key" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
          placeholder={user.hasAiKey ? `\u2022\u2022\u2022\u2022${user.aiKeyLast4}` : 'Enter API key'} />
        {!user.hasAiKey && user.hasGlobalAiKey && (
          <p className="text-xs text-muted-foreground">A global API key is configured. AI features work without setting your own key.</p>
        )}
      </div>
      <div className="border-t border-border pt-3 mt-3 flex flex-col gap-2">
        {status === 'saving' && <span className="text-xs text-muted-foreground animate-pulse text-right">Saving...</span>}
        {status === 'saved' && <span className="text-xs text-green-400 text-right">Saved</span>}
        <Button type="button" variant="destructive" className="w-full" onClick={handleClear} loading={loading}>Clear All</Button>
      </div>
    </Card>
  );
}
