import { useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { useOnboardingStore } from '@/stores/onboardingStore';

/** Replays the welcome tour. The tour itself is mounted in Layout. */
export default function OnboardingSettings() {
  const { t } = useTranslation('settings');
  const start = useOnboardingStore((s) => s.start);

  return (
    <Card>
      <h3 className="text-sm font-semibold mb-1">{t('onboarding.heading')}</h3>
      <p className="text-xs text-muted-foreground mb-3">{t('onboarding.description')}</p>
      {/* Full width, like every other action button on this page. */}
      <Button variant="outline" className="w-full" onClick={start} data-testid="replay-tour">
        {t('onboarding.button')}
      </Button>
    </Card>
  );
}
