import { useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';

export default function Imprint() {
  const { t } = useTranslation('landing');

  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">{t('imprint.heading')}</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <div className="space-y-4">
            <h3 className="font-semibold text-foreground">{t('imprint.ddgNotice.heading')}</h3>
            {/* Address and email are rendered as server-generated SVGs as a
                deliberate protection against address/email harvesting bots. */}
            <img src="/imprint/address.svg" alt={t('imprint.ddgNotice.addressAlt')} className="max-w-full" />
            <img src="/imprint/email.svg" alt={t('imprint.ddgNotice.emailAlt')} className="max-w-full" />
          </div>

          <div className="space-y-4">
            <h3 className="font-semibold text-foreground">{t('imprint.responsibleForContent.heading')}</h3>
            <img src="/imprint/address.svg" alt={t('imprint.responsibleForContent.addressAlt')} className="max-w-full" />
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold text-foreground">{t('imprint.disputeResolution.heading')}</h3>
            <p>{t('imprint.disputeResolution.body')}</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
