import { useState, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { getSettings, importData } from '@/api/settings';
import { getCsrfToken } from '@/api/client';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import MacroSettings from './MacroSettings';
import PreferencesSettings from './PreferencesSettings';
import PasswordSettings from './PasswordSettings';
import TwoFactorSettings from './TwoFactorSettings';
import EmailSettings from './EmailSettings';
import AISettings from './AISettings';
import LinkSettings from './LinkSettings';
import TodoSettings from './TodoSettings';
import NoteSettings from './NoteSettings';

export default function Settings() {
  const { isLoading: authLoading } = useRequireAuth();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importMessage, setImportMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  });

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center p-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['settings'] });
    queryClient.invalidateQueries({ queryKey: ['me'] });
  };

  const handleImport = async () => {
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    setImportLoading(true);
    setImportMessage(null);
    try {
      const csrfToken = await getCsrfToken();
      const result = await importData(file, csrfToken);
      if (result.ok) {
        setImportMessage({ type: 'success', text: result.message || 'Data imported successfully.' });
        refresh();
      } else {
        setImportMessage({ type: 'error', text: result.error || 'Import failed.' });
      }
    } catch {
      setImportMessage({ type: 'error', text: 'Import failed.' });
    }
    setImportLoading(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Feedback alerts */}
      {data.linkFeedback && <Alert type={data.linkFeedback.type as 'success' | 'error'} message={data.linkFeedback.message} />}
      {data.passwordFeedback && <Alert type={data.passwordFeedback.type as 'success' | 'error'} message={data.passwordFeedback.message} />}
      {data.aiFeedback && <Alert type={data.aiFeedback.type as 'success' | 'error'} message={data.aiFeedback.message} />}
      {data.emailFeedback && <Alert type={data.emailFeedback.type as 'success' | 'error'} message={data.emailFeedback.message} />}
      {data.importFeedback && <Alert type={data.importFeedback.type as 'success' | 'error'} message={data.importFeedback.message} />}

      {/* Two columns on desktop, single on mobile. Each column flows independently. */}
      <div className="columns-1 gap-4 space-y-4 md:columns-2">
        <div className="break-inside-avoid">
          <MacroSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <PreferencesSettings user={data.user} timezones={data.timezones} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <TodoSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <NoteSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <AISettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <EmailSettings currentEmail={data.user.email} totpEnabled={data.user.totpEnabled} />
        </div>
        <div className="break-inside-avoid">
          <PasswordSettings totpEnabled={data.user.totpEnabled} />
        </div>
        <div className="break-inside-avoid">
          <TwoFactorSettings totpEnabled={data.user.totpEnabled} onUpdate={refresh} />
        </div>
        <div className="break-inside-avoid">
          <LinkSettings
            incomingRequests={data.incomingRequests}
            outgoingRequests={data.outgoingRequests}
            acceptedLinks={data.acceptedLinks}
            availableSlots={data.availableSlots}
            onUpdate={refresh}
          />
        </div>
        <div className="break-inside-avoid">
          <Card>
            <h3 className="text-sm font-semibold mb-3">Data</h3>
            <div className="flex flex-col gap-3">
              <a href="/settings/export" className="text-sm text-primary hover:underline">Export JSON</a>
              <div className="border-t border-border pt-3">
                <p className="text-xs text-muted-foreground mb-2">Import from a JSON backup. This replaces all existing entries.</p>
                {importMessage && <Alert type={importMessage.type} message={importMessage.text} className="mb-2" />}
                <div className="flex items-center gap-2 flex-wrap">
                  <input ref={fileInputRef} type="file" accept=".json,application/json" className="text-xs text-muted-foreground file:mr-2 file:rounded-md file:border-0 file:bg-muted file:px-3 file:py-1.5 file:text-xs file:text-foreground file:cursor-pointer" />
                  <Button size="sm" variant="destructive" onClick={handleImport} loading={importLoading}>Import</Button>
                </div>
              </div>
            </div>
          </Card>
        </div>
        <div className="break-inside-avoid">
          <Card>
            <h3 className="text-sm font-semibold mb-2 text-destructive">Danger Zone</h3>
            <p className="text-xs text-muted-foreground mb-3">Permanently delete your account and all data.</p>
            <a href="/delete"><Button size="sm" variant="destructive">Delete Account</Button></a>
          </Card>
        </div>
      </div>
    </div>
  );
}
