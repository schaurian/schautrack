import { useState, useRef, useCallback, useEffect } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { useSearchParams } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useRequireAuth } from '@/hooks/useAuth';
import { useLogout } from '@/hooks/useLogout';
import { useAuthStore } from '@/stores/authStore';
import { getSettings, importData, exportData } from '@/api/settings';
import { ApiError } from '@/api/client';
import { useToastStore } from '@/stores/toastStore';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { QueryError } from '@/components/ui/QueryError';
import EmailSettings from '../Settings/EmailSettings';
import PasswordSettings from '../Settings/PasswordSettings';
import TwoFactorSettings from '../Settings/TwoFactorSettings';
import PasskeySettings from '../Settings/PasskeySettings';
import OIDCSettings from '../Settings/OIDCSettings';
import ReportIssueCard from '../Settings/ReportIssueCard';

/**
 * Identity, credentials and data ownership. Split out of Settings so that page
 * can stay about tracking (goals, macros, units) — the things tuned while using
 * the app — instead of mixing them with things set once at signup.
 *
 * This is also the app's single logout. It previously existed twice: a sidebar
 * button on desktop and an `lg:hidden` row in Settings on mobile.
 */
export default function Account() {
  const { t } = useTranslation('settings');
  const doLogout = useLogout();
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

  // The OIDC link flow redirects back here with ?error=/?success=; surface them
  // as toasts then strip the params so a refresh doesn't replay them.
  useEffect(() => {
    const errorCode = searchParams.get('error');
    const successCode = searchParams.get('success');
    if (!errorCode && !successCode) return;
    if (errorCode) {
      const msg = t('oidc.errors.' + errorCode, { defaultValue: t('oidc.genericError') });
      addToast('error', msg);
    }
    if (successCode) {
      const msg = t('oidc.success.' + successCode, { defaultValue: '' });
      if (msg) addToast('success', msg);
    }
    const next = new URLSearchParams(searchParams);
    next.delete('error');
    next.delete('success');
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams, addToast, t]);

  const handleFileChange = useCallback(() => {
    const file = fileInputRef.current?.files?.[0];
    setSelectedFileName(file ? file.name : null);
    setImportMessage(null);
  }, []);

  // Same query key as Settings — the cache is shared, so moving between the two
  // pages costs no extra fetch.
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
        setImportMessage({ type: 'success', text: result.message || t('data.importSuccess') });
        refresh();
      } else {
        setImportMessage({ type: 'error', text: result.error || t('data.importFailed') });
      }
    } catch (err) {
      setImportMessage({
        type: 'error',
        text: err instanceof ApiError ? err.message : t('data.importFailed'),
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

  // No identity header here: the first card (EmailSettings) already states
  // "Current: <email>", and rendering the address twice on one page is the same
  // redundancy the sidebar user block had. If a profile picture lands later,
  // that is the point to add a header — with the avatar only.
  return (
    <div className="flex flex-col gap-4" data-testid="account-page">
      {data.passwordFeedback && <Alert type={data.passwordFeedback.type as 'success' | 'error'} message={data.passwordFeedback.message} />}
      {data.emailFeedback && <Alert type={data.emailFeedback.type as 'success' | 'error'} message={data.emailFeedback.message} />}
      {data.importFeedback && <Alert type={data.importFeedback.type as 'success' | 'error'} message={data.importFeedback.message} />}

      <div className="flex flex-col gap-3">
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
          <Card>
            <h3 className="text-sm font-semibold mb-4">{t('data.heading')}</h3>
            <div className="flex flex-col gap-4">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">{t('data.exportLabel')}</p>
                <p className="text-xs text-muted-foreground mb-3">{t('data.exportDescription')}</p>
                <Button variant="outline" className="w-full" onClick={handleExport} loading={exportLoading}>
                  {t('data.exportButton')}
                </Button>
              </div>
              <div className="border-t border-border pt-4">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">{t('data.importLabel')}</p>
                <p className="text-xs text-muted-foreground mb-3">{t('data.importDescription')}</p>
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
                  {selectedFileName ?? t('data.chooseFile')}
                </button>
                <Button
                  variant="destructive"
                  className="w-full"
                  onClick={() => setConfirmImportOpen(true)}
                  loading={importLoading}
                  disabled={!selectedFileName}
                >
                  {t('data.importButton')}
                </Button>
              </div>
            </div>
          </Card>
        </div>

        {/* Import wipes every existing entry. Step-up has a grace window, so
            re-auth alone would let someone who just authenticated for an
            unrelated setting replace their history with one mis-click. Require
            an explicit confirmation independent of step-up state. */}
        <Dialog.Root open={confirmImportOpen} onOpenChange={setConfirmImportOpen}>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
            <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-card p-6 text-card-foreground shadow-lg focus:outline-none">
              <Dialog.Title className="text-base font-semibold mb-1 text-destructive">{t('confirmImport.title')}</Dialog.Title>
              <Dialog.Description className="text-sm text-muted-foreground mb-4">
                {t('confirmImport.descriptionPrefix')}{selectedFileName ? <> <span className="font-medium text-foreground">{selectedFileName}</span></> : ''} {t('confirmImport.descriptionSuffix')}
              </Dialog.Description>
              <div className="flex flex-col gap-2">
                <Button variant="destructive" className="w-full" onClick={handleImport} loading={importLoading}>
                  {t('confirmImport.replaceAll')}
                </Button>
                <Dialog.Close asChild>
                  <Button type="button" variant="ghost" size="sm" className="w-full border border-border hover:border-foreground/40">
                    {t('confirmImport.cancel')}
                  </Button>
                </Dialog.Close>
              </div>
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>

        <div className="break-inside-avoid">
          <Card>
            <h3 className="text-sm font-semibold mb-2 text-destructive">{t('danger.heading')}</h3>
            <p className="text-xs text-muted-foreground mb-3">{t('danger.description')}</p>
            <div className="border-t border-border pt-3 mt-1">
              <a href="/delete"><Button variant="destructive" className="w-full">{t('danger.deleteAccount')}</Button></a>
            </div>
          </Card>
        </div>

        <div className="break-inside-avoid">
          <ReportIssueCard />
        </div>

        {/* The app's only logout. Ghost inside a surface card like every other
            row here — logging out is routine, so it shouldn't carry a button
            border that competes with Delete account right above it. */}
        <div className="break-inside-avoid">
          <Card className="p-2 sm:p-2">
            <Button variant="ghost" className="w-full" onClick={doLogout}>
              {t('account.logout')}
            </Button>
          </Card>
        </div>
      </div>
    </div>
  );
}
