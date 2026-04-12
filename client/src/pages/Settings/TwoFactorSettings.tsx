import { useState } from 'react';
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
  const [setupData, setSetupData] = useState<{ qrDataUrl: string; secret: string } | null>(null);
  const [token, setToken] = useState('');
  const [disableToken, setDisableToken] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [regenToken, setRegenToken] = useState('');
  const [regenLoading, setRegenLoading] = useState(false);
  const [showRegen, setShowRegen] = useState(false);

  const handleSetup = async () => {
    setError('');
    setLoading(true);
    try {
      const res = await setup2fa();
      if (res.ok && res.qrDataUrl && res.secret) {
        setSetupData({ qrDataUrl: res.qrDataUrl, secret: res.secret });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Setup failed.');
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
          setSuccess('2FA enabled. Save your backup codes below.');
        } else {
          setSuccess('2FA enabled successfully.');
        }
        onUpdate();
      } else {
        setError(res.error || 'Invalid code.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to enable 2FA.');
    }
    setLoading(false);
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const payload = useBackupCode
        ? { backup_code: disableToken }
        : { token: disableToken };
      const res = await disable2fa(payload);
      if (res.ok) {
        setSuccess('2FA disabled.');
        setDisableToken('');
        setBackupCodes(null);
        setUseBackupCode(false);
        onUpdate();
      } else {
        setError(res.error || 'Invalid code.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to disable 2FA.');
    }
    setLoading(false);
  };

  const handleRegenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setRegenLoading(true);
    try {
      const res = await regenerateBackupCodes({ token: regenToken });
      if (res.ok && res.backupCodes) {
        setBackupCodes(res.backupCodes);
        setSuccess('New backup codes generated. Save them now.');
        setRegenToken('');
        setShowRegen(false);
      } else {
        setError(res.error || 'Invalid code.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to regenerate codes.');
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
      <h3 className="text-base font-semibold mb-4">Two-Factor Authentication</h3>
      {error && <Alert type="error" message={error} />}
      {success && <Alert type="success" message={success} />}

      {backupCodes && (
        <div className="flex flex-col gap-3 mb-4 p-3 rounded-md border border-border bg-muted/20">
          <p className="text-sm font-medium text-foreground">Backup Codes</p>
          <p className="text-xs text-muted-foreground">
            Save these codes somewhere safe. Each code can only be used once to sign in if you lose your authenticator.
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
              {copied ? 'Copied!' : 'Copy All'}
            </Button>
            <Button size="sm" variant="ghost" onClick={handleDownloadCodes}>
              Download
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setBackupCodes(null)}>
              Done
            </Button>
          </div>
        </div>
      )}

      {totpEnabled ? (
        <>
          <p className="text-muted-foreground text-sm mb-3">
            2FA is enabled on your account.
          </p>
          <form onSubmit={handleDisable} className="flex flex-col gap-3">
            <Input
              label={useBackupCode ? 'Backup Code' : '2FA Code'}
              value={disableToken}
              onChange={(e) => setDisableToken(e.target.value)}
              inputMode={useBackupCode ? 'numeric' : 'numeric'}
              maxLength={useBackupCode ? 8 : 6}
              placeholder={useBackupCode ? 'Enter 8-digit backup code' : 'Enter 6-digit code'}
              required
            />
            <button
              type="button"
              onClick={() => { setUseBackupCode(!useBackupCode); setDisableToken(''); }}
              className="text-xs text-primary hover:underline text-left"
            >
              {useBackupCode ? 'Use authenticator code instead' : 'Lost your authenticator? Use a backup code'}
            </button>
            <div className="border-t border-border pt-3 mt-1">
              <Button type="submit" variant="destructive" className="w-full" loading={loading}>Disable 2FA</Button>
            </div>
          </form>

          <div className="mt-4 pt-4 border-t border-border">
            {showRegen ? (
              <form onSubmit={handleRegenerate} className="flex flex-col gap-3">
                <Input
                  label="2FA Code to confirm"
                  value={regenToken}
                  onChange={(e) => setRegenToken(e.target.value)}
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="Enter 6-digit code"
                  required
                />
                <div className="border-t border-border pt-3 mt-1 flex gap-2">
                  <Button type="button" variant="ghost" className="flex-1" onClick={() => { setShowRegen(false); setRegenToken(''); }}>Cancel</Button>
                  <Button type="submit" className="flex-1" loading={regenLoading}>Regenerate</Button>
                </div>
              </form>
            ) : (
              <button
                type="button"
                onClick={() => setShowRegen(true)}
                className="text-xs text-muted-foreground hover:text-primary transition-colors"
              >
                Regenerate backup codes
              </button>
            )}
          </div>
        </>
      ) : setupData ? (
        <div className="flex flex-col gap-3 items-center">
          <p className="text-muted-foreground text-sm text-center">
            Scan this QR code with your authenticator app:
          </p>
          <img src={setupData.qrDataUrl} alt="2FA QR Code" className="w-[200px] h-[200px] rounded-lg" />
          <div className="flex items-center gap-2">
            <code className="text-xs text-muted-foreground bg-surface px-2 py-1 rounded break-all">
              {setupData.secret}
            </code>
            <button
              type="button"
              onClick={handleCopySecret}
              className="bg-transparent border-none text-primary cursor-pointer text-xs whitespace-nowrap"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <form onSubmit={handleEnable} className="flex flex-col gap-3 w-full">
            <Input
              label="Verification Code"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              inputMode="numeric"
              maxLength={6}
              placeholder="Enter 6-digit code"
              required
            />
            <div className="border-t border-border pt-3 mt-1 flex gap-2">
              <Button type="button" variant="ghost" className="flex-1" onClick={handleCancel}>Cancel</Button>
              <Button type="submit" className="flex-1" loading={loading}>Activate</Button>
            </div>
          </form>
        </div>
      ) : (
        <div className="border-t border-border pt-3 mt-1">
          <Button className="w-full" onClick={handleSetup} loading={loading}>Setup 2FA</Button>
        </div>
      )}
    </Card>
  );
}
