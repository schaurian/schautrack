import { useTranslation, Trans } from 'react-i18next';
import { Card } from '@/components/ui/Card';

export default function Terms() {
  const { t } = useTranslation('landing');
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">{t('terms.heading')}</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <p>{t('terms.intro')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.service.heading')}</h3>
          <p>{t('terms.service.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.notMedicalAdvice.heading')}</h3>
          <p>{t('terms.notMedicalAdvice.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.yourAccount.heading')}</h3>
          <p>{t('terms.yourAccount.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.accountLinking.heading')}</h3>
          <p>{t('terms.accountLinking.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.thirdPartyData.heading')}</h3>
          <p>
            <Trans
              i18nKey="terms.thirdPartyData.body"
              t={t}
              components={{
                linkOff: <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
                linkOdbl: <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline" />,
              }}
            />
          </p>

          <h3 className="font-semibold text-foreground">{t('terms.acceptableUse.heading')}</h3>
          <p>{t('terms.acceptableUse.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.changes.heading')}</h3>
          <p>{t('terms.changes.body')}</p>

          <h3 className="font-semibold text-foreground">{t('terms.governingLaw.heading')}</h3>
          <p>{t('terms.governingLaw.body')}</p>
        </div>
      </Card>
    </div>
  );
}
