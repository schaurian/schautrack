import { useTranslation, Trans } from 'react-i18next';
import { Card } from '@/components/ui/Card';

export default function Privacy() {
  const { t } = useTranslation('landing');
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">{t('privacy.heading')}</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <p>{t('privacy.intro')}</p>

          <h3 className="font-semibold text-foreground">{t('privacy.dataWeCollect.heading')}</h3>
          <ul className="list-disc pl-6">
            <li>{t('privacy.dataWeCollect.items.email')}</li>
            <li>{t('privacy.dataWeCollect.items.entries')}</li>
            <li>{t('privacy.dataWeCollect.items.notes')}</li>
            <li>{t('privacy.dataWeCollect.items.preferences')}</li>
            <li>{t('privacy.dataWeCollect.items.authMaterial')}</li>
          </ul>

          <h3 className="font-semibold text-foreground">{t('privacy.cookies.heading')}</h3>
          <p>
            <Trans i18nKey="privacy.cookies.body" t={t} components={{ code: <code /> }} />
          </p>

          <h3 className="font-semibold text-foreground">{t('privacy.logsSecurity.heading')}</h3>
          <p>{t('privacy.logsSecurity.body')}</p>

          <h3 className="font-semibold text-foreground">{t('privacy.accountLinking.heading')}</h3>
          <p>{t('privacy.accountLinking.body')}</p>

          <h3 className="font-semibold text-foreground">{t('privacy.subprocessors.heading')}</h3>
          <p>{t('privacy.subprocessors.intro')}</p>
          <ul className="list-disc pl-6">
            <li>
              <Trans i18nKey="privacy.subprocessors.items.aiEstimation" t={t} components={{ strong: <strong /> }} />
            </li>
            <li>
              <Trans
                i18nKey="privacy.subprocessors.items.barcodeLookups"
                t={t}
                components={{
                  strong: <strong />,
                  linkOff: <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
                  linkOdbl: <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
                }}
              />
            </li>
            <li><Trans i18nKey="privacy.subprocessors.items.hosting" t={t} components={{ strong: <strong /> }} /></li>
            <li><Trans i18nKey="privacy.subprocessors.items.emailDelivery" t={t} components={{ strong: <strong /> }} /></li>
            <li><Trans i18nKey="privacy.subprocessors.items.backups" t={t} components={{ strong: <strong /> }} /></li>
          </ul>
          <h3 className="font-semibold text-foreground">{t('privacy.internationalTransfers.heading')}</h3>
          <p>{t('privacy.internationalTransfers.body')}</p>

          <h3 className="font-semibold text-foreground">{t('privacy.retention.heading')}</h3>
          <ul className="list-disc pl-6">
            <li>{t('privacy.retention.items.entries')}</li>
            <li>{t('privacy.retention.items.sessions')}</li>
            <li>{t('privacy.retention.items.auditLog')}</li>
            <li>{t('privacy.retention.items.accountDeletion')}</li>
          </ul>

          <h3 className="font-semibold text-foreground">{t('privacy.dataWeDontCollect.heading')}</h3>
          <ul className="list-disc pl-6">
            <li>{t('privacy.dataWeDontCollect.items.noAnalytics')}</li>
            <li>{t('privacy.dataWeDontCollect.items.noThirdPartyCookies')}</li>
            <li>{t('privacy.dataWeDontCollect.items.noDataSold')}</li>
          </ul>

          <h3 className="font-semibold text-foreground">{t('privacy.rights.heading')}</h3>
          <p>
            <Trans
              i18nKey="privacy.rights.body1"
              t={t}
              components={{ linkImprint: <a href="/imprint" className="text-primary underline" /> }}
            />
          </p>
          <p>
            <Trans
              i18nKey="privacy.rights.body2"
              t={t}
              components={{
                linkBayLDA: <a href="https://www.lda.bayern.de/" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
              }}
            />
          </p>
        </div>
      </Card>
    </div>
  );
}
