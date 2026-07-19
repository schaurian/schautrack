import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { setup2fa, enable2fa, disable2fa, regenerateBackupCodes } from '@/api/settings';
import { ApiError } from '@/api/client';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface Props {
  totpEnabled: boolean;
  onUpdate: () => void;
}

export default function TwoFactorSettings({ totpEnabled, onUpdate }: Props) {
  const { t } = useTranslation('settings');
  const [setupData, setSetupData] = useState<{ qrDataUrl: string; secret: string } | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [regenLoading, setRegenLoading] = useState(false);

  const handleSetup = async () => {
    setError('');
    setLoading(true);
    try {
      const res = await setup2fa();
      if (res.ok && res.qrDataUrl && res.secret) {
        setSetupData({ qrDataUrl: res.qrDataUrl, secret: res.secret });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('twofa.setupFailed'));
    }
    setLoading(false);
  };

  const handleEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await enable2fa({ token });
      if (res.ok) {
        setSetupData(null);
        setToken('');
        if (res.backupCodes) {
          setBackupCodes(res.backupCodes);
          setSuccess(t('twofa.enabledWithCodes'));
        } else {
          setSuccess(t('twofa.enabledSuccess'));
        }
        onUpdate();
      } else {
        setError(res.error || t('twofa.invalidCode'));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('twofa.enableFailed'));
    }
    setLoading(false);
  };

  const handleDisable = async () => {
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const res = await disable2fa();
      if (res.ok) {
        setSuccess(t('twofa.disabled'));
        setBackupCodes(null);
        onUpdate();
      } else {
        setError(res.error || t('twofa.disableFailed'));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('twofa.disableFailed'));
    }
    setLoading(false);
  };

  const handleRegenerate = async () => {
    setError('');
    setRegenLoading(true);
    try {
      const res = await regenerateBackupCodes();
      if (res.ok && res.backupCodes) {
        setBackupCodes(res.backupCodes);
        setSuccess(t('twofa.regenerated'));
      } else {
        setError(res.error || t('twofa.regenerateFailed'));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('twofa.regenerateFailed'));
    }
    setRegenLoading(false);
  };

  const handleCopySecret = async () => {
    if (!setupData) return;
    try {
      await navigator.clipboard.writeText(setupData.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard not available */ }
  };

  const handleCopyCodes = async () => {
    if (!backupCodes) return;
    try {
      await navigator.clipboard.writeText(backupCodes.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard not available */ }
  };

  const handleDownloadCodes = () => {
    if (!backupCodes) return;
    const blob = new Blob([backupCodes.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'schautrack-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCancel = () => {
    setSetupData(null);
    setToken('');
    setError('');
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">{t('twofa.heading')}</h3>
      {error && <Alert type="error" message={error} />}
      {success && <Alert type="success" message={success} />}

      {backupCodes && (
        <div className="flex flex-col gap-3 mb-4 p-3 rounded-md border border-border bg-muted/20">
          <p className="text-sm font-medium text-foreground">{t('twofa.backupCodesTitle')}</p>
          <p className="text-xs text-muted-foreground">
            {t('twofa.backupCodesDescription')}
          </p>
          <div className="grid grid-cols-2 gap-1">
            {backupCodes.map((code) => (
              <code key={code} className="text-xs font-mono text-foreground bg-surface px-2 py-1 rounded text-center">
                {code}
              </code>
            ))}
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={handleCopyCodes}>
              {copied ? t('twofa.copied') : t('twofa.copyAll')}
            </Button>
            <Button size="sm" variant="ghost" onClick={handleDownloadCodes}>
              {t('twofa.download')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setBackupCodes(null)}>
              {t('twofa.done')}
            </Button>
          </div>
        </div>
      )}

      {totpEnabled ? (
        <>
          <p className="text-muted-foreground text-sm mt-3 mb-3">
            {t('twofa.enabledNotice')}
          </p>
          <div className="border-t border-border pt-3 mt-1">
            <Button type="button" variant="destructive" className="w-full" loading={loading} onClick={handleDisable}>
              {t('twofa.disableButton')}
            </Button>
          </div>

          <div className="mt-4 pt-4 border-t border-border">
            <button
              type="button"
              onClick={handleRegenerate}
              disabled={regenLoading}
              className="text-xs text-muted-foreground hover:text-primary transition-colors disabled:opacity-50"
            >
              {regenLoading ? t('twofa.regenerating') : t('twofa.regenerateBackupCodes')}
            </button>
          </div>
        </>
      ) : setupData ? (
        <div className="flex flex-col gap-3 items-center">
          <p className="text-muted-foreground text-sm text-center">
            {t('twofa.scanQr')}
          </p>
          <img src={setupData.qrDataUrl} alt={t('twofa.qrAlt')} className="w-[200px] h-[200px] rounded-lg" />
          <div className="flex items-center gap-2">
            <code className="text-xs text-muted-foreground bg-surface px-2 py-1 rounded break-all">
              {setupData.secret}
            </code>
            <button
              type="button"
              onClick={handleCopySecret}
              className="bg-transparent border-none text-primary cursor-pointer text-xs whitespace-nowrap"
            >
              {copied ? t('twofa.copied') : t('twofa.copy')}
            </button>
          </div>
          <form onSubmit={handleEnable} className="flex flex-col gap-3 w-full">
            <Input
              label={t('twofa.verificationCodeLabel')}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              inputMode="numeric"
              maxLength={6}
              placeholder={t('twofa.verificationCodePlaceholder')}
              required
            />
            <div className="border-t border-border pt-3 mt-1 flex gap-2">
              <Button type="button" variant="ghost" className="flex-1" onClick={handleCancel}>{t('twofa.cancel')}</Button>
              <Button type="submit" className="flex-1" loading={loading}>{t('twofa.activate')}</Button>
            </div>
          </form>
        </div>
      ) : (
        <div className="border-t border-border pt-3 mt-1">
          <Button className="w-full" onClick={handleSetup} loading={loading}>{t('twofa.setupButton')}</Button>
        </div>
      )}
    </Card>
  );
}
