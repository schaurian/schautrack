import { useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';

export default function Imprint() {
  const { t } = useTranslation('landing');
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">{t('imprint.heading')}</h1>
        <div className="space-y-4 text-sm leading-relaxed text-muted-foreground">
          <img src="/imprint/address.svg" alt={t('imprint.addressAlt')} className="max-w-full" />
          <img src="/imprint/email.svg" alt={t('imprint.emailAlt')} className="max-w-full" />
        </div>
      </Card>
    </div>
  );
}
