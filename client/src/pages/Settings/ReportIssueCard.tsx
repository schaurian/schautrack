import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { useVersionInfo } from '@/hooks/useVersionInfo';
import { buildNewIssueUrl, canReportIssue } from '@/lib/version';

/** Markdown body pre-filled into the new issue, with environment details that make
 *  triage easier. Built client-side so it can include the live browser/page. */
function buildIssueBody(version: string | null): string {
  return [
    `**Version:** ${version ? `v${version}` : 'unknown'}`,
    `**Browser:** ${navigator.userAgent}`,
    `**Page:** ${window.location.href}`,
    '',
    '**Describe the issue:**',
    '',
    '**Steps to reproduce:**',
    '',
  ].join('\n');
}

export default function ReportIssueCard() {
  const { t } = useTranslation('settings');
  const { current, latest, outdated, issuesUrl, newIssueUrlTemplate, loading } = useVersionInfo();
  const [acknowledged, setAcknowledged] = useState(false);

  const displayVersion = current
    ? current.startsWith('staging') || current === 'dev'
      ? current
      : `v${current}`
    : null;

  const allowed = canReportIssue({
    hasTemplate: !!newIssueUrlTemplate,
    loading,
    outdated,
    acknowledged,
  });

  const handleReport = () => {
    if (!newIssueUrlTemplate) return;
    const url = buildNewIssueUrl(newIssueUrlTemplate, '', buildIssueBody(current));
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-2">{t('reportIssue.title')}</h3>
      <p className="text-xs text-muted-foreground mb-3">
        {t('reportIssue.description')}
      </p>

      {displayVersion && (
        <p className="text-xs mb-3">
          <span className="text-muted-foreground">{t('reportIssue.yourVersion')}</span>
          <span className={outdated ? 'font-medium text-destructive' : 'text-foreground'}>
            {displayVersion}
          </span>
          {outdated && latest && (
            <span className="text-muted-foreground">{t('reportIssue.latestAvailable', { latest })}</span>
          )}
        </p>
      )}

      {outdated && (
        <div className="mb-3 rounded-[10px] border border-destructive/30 bg-destructive/5 p-3">
          <p className="text-xs text-muted-foreground mb-2">
            <Trans
              t={t}
              i18nKey="reportIssue.olderVersion"
              components={{
                issues: issuesUrl ? (
                  <a
                    href={issuesUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  />
                ) : (
                  <span />
                ),
              }}
            />
          </p>
          <label className="flex items-start gap-2 text-xs text-foreground cursor-pointer">
            <input
              type="checkbox"
              className="mt-0.5 size-4 shrink-0 accent-primary"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
            />
            <span>
              <Trans t={t} i18nKey="reportIssue.acknowledgement" values={{ version: displayVersion }} />
            </span>
          </label>
        </div>
      )}

      <Button variant="outline" className="w-full" onClick={handleReport} disabled={!allowed}>
        {t('reportIssue.submit')}
      </Button>
    </Card>
  );
}
