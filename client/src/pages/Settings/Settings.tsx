import { useState, useRef, useCallback, useEffect } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { useSearchParams } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { useAuthStore } from '@/stores/authStore';
import { getSettings, importData, exportData } from '@/api/settings';
import { ApiError } from '@/api/client';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { QueryError } from '@/components/ui/QueryError';
import { OIDC_SETTINGS_ERRORS, OIDC_SETTINGS_SUCCESS } from '@/lib/oidcMessages';
import MacroSettings from './MacroSettings';
import PreferencesSettings from './PreferencesSettings';
import PasswordSettings from './PasswordSettings';
import TwoFactorSettings from './TwoFactorSettings';
import EmailSettings from './EmailSettings';
import AISettings from './AISettings';
import LinkSettings from './LinkSettings';
import TodoSettings from './TodoSettings';
import NoteSettings from './NoteSettings';
import SavedFoodsSettings from './SavedFoodsSettings';
import PasskeySettings from './PasskeySettings';
import OIDCSettings from './OIDCSettings';

export default function Settings() {
  const { isLoading: authLoading } = useRequireAuth();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importMessage, setImportMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [confirmImportOpen, setConfirmImportOpen] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const addToast = useToastStore((s) => s.addToast);

  // Surface OIDC link-flow outcomes (?error=... / ?success=...) as toasts,
  // then strip the params so a refresh doesn't fire them again.
  useEffect(() => {
    const errorCode = searchParams.get('error');
    const successCode = searchParams.get('success');
    if (!errorCode && !successCode) return;
    if (errorCode) {
      const msg = OIDC_SETTINGS_ERRORS[errorCode] ?? 'Something went wrong.';
      addToast('error', msg);
    }
    if (successCode) {
      const msg = OIDC_SETTINGS_SUCCESS[successCode];
      if (msg) addToast('success', msg);
    }
    const next = new URLSearchParams(searchParams);
    next.delete('error');
    next.delete('success');
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams, addToast]);

  const handleFileChange = useCallback(() => {
    const file = fileInputRef.current?.files?.[0];
    setSelectedFileName(file ? file.name : null);
    setImportMessage(null);
  }, []);

  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  });

  if (isError && !data) {
    return <QueryError error={error} onRetry={() => refetch()} retrying={isFetching} />;
  }

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center p-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['settings'] });
    // The current user lives in the auth store, not a query — re-fetch it
    // so changes (macros, preferences, …) propagate app-wide.
    useAuthStore.getState().fetchUser();
  };

  const handleImport = async () => {
    setConfirmImportOpen(false);
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    setImportLoading(true);
    setImportMessage(null);
    try {
      const result = await importData(file);
      if (result.ok) {
        setImportMessage({ type: 'success', text: result.message || 'Data imported successfully.' });
        refresh();
      } else {
        setImportMessage({ type: 'error', text: result.error || 'Import failed.' });
      }
    } catch (err) {
      setImportMessage({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Import failed.',
      });
    }
    setImportLoading(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setSelectedFileName(null);
  };

  const handleExport = async () => {
    setExportLoading(true);
    try {
      await exportData();
    } catch {
      // step-up cancellation lands here as ApiError(403). Quiet failure.
    }
    setExportLoading(false);
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
          <SavedFoodsSettings />
        </div>
        <div className="break-inside-avoid">
          <AISettings user={data.user} onSave={refresh} />
        </div>
        {data.user.authMethod !== 'oidc' && (
          <>
            <div className="break-inside-avoid">
              <EmailSettings currentEmail={data.user.email} />
            </div>
            <div className="break-inside-avoid">
              <PasswordSettings />
            </div>
            <div className="break-inside-avoid">
              <TwoFactorSettings totpEnabled={data.user.totpEnabled} onUpdate={refresh} />
            </div>
            <div className="break-inside-avoid">
              <PasskeySettings onUpdate={refresh} />
            </div>
            <div className="break-inside-avoid">
              <OIDCSettings linked={data.user.oidcLinked || false} onUpdate={refresh} />
            </div>
          </>
        )}
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
            <h3 className="text-sm font-semibold mb-4">Data</h3>
            <div className="flex flex-col gap-4">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Export</p>
                <p className="text-xs text-muted-foreground mb-3">Download all your entries as a JSON backup.</p>
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={handleExport}
                  loading={exportLoading}
                >
                  Export JSON
                </Button>
              </div>
              <div className="border-t border-border pt-4">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Import</p>
                <p className="text-xs text-muted-foreground mb-3">Restore from a JSON backup. This replaces all existing entries.</p>
                {importMessage && <Alert type={importMessage.type} message={importMessage.text} className="mb-3" />}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={handleFileChange}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full rounded-[10px] border border-dashed border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground hover:border-ring hover:text-foreground transition-colors cursor-pointer mb-3 text-left truncate"
                >
                  {selectedFileName ?? 'Choose a file…'}
                </button>
                <Button
                  variant="destructive"
                  className="w-full"
                  onClick={() => setConfirmImportOpen(true)}
                  loading={importLoading}
                  disabled={!selectedFileName}
                >
                  Import
                </Button>
              </div>
            </div>
          </Card>
        </div>

        {/* Import is destructive — it wipes every existing entry. Step-up has a
            grace window, so gating on re-auth alone lets a user who just
            authenticated for any other setting replace their whole history with
            one mis-click. Require an explicit in-app confirmation, independent
            of step-up state. */}
        <Dialog.Root open={confirmImportOpen} onOpenChange={setConfirmImportOpen}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
            <Dialog.Content
              className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-card p-6 text-card-foreground shadow-lg focus:outline-none"
            >
              <Dialog.Title className="text-base font-semibold mb-1 text-destructive">Replace all entries?</Dialog.Title>
              <Dialog.Description className="text-sm text-muted-foreground mb-4">
                Importing{selectedFileName ? <> <span className="font-medium text-foreground">{selectedFileName}</span></> : ''} will permanently delete all of your existing entries and replace them with the contents of this file. This cannot be undone.
              </Dialog.Description>
              <div className="flex flex-col gap-2">
                <Button
                  variant="destructive"
                  className="w-full"
                  onClick={handleImport}
                  loading={importLoading}
                >
                  Replace all entries
                </Button>
                <Dialog.Close asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="w-full border border-border hover:border-foreground/40"
                  >
                    Cancel
                  </Button>
                </Dialog.Close>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
        <div className="break-inside-avoid">
          <Card>
            <h3 className="text-sm font-semibold mb-2 text-destructive">Danger Zone</h3>
            <p className="text-xs text-muted-foreground mb-3">Permanently delete your account and all data.</p>
            <div className="border-t border-border pt-3 mt-1">
              <a href="/delete"><Button variant="destructive" className="w-full">Delete Account</Button></a>
            </div>
          </Card>
        </div>
      </div>

      <p className="text-center text-xs text-muted-foreground">
        Spotted a bug or missing a feature?{' '}
        <a
          href="https://github.com/schaurian/schautrack/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline"
        >
          Open an issue on GitHub
        </a>
      </p>
    </div>
  );
}
