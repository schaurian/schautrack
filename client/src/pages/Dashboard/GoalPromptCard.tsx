import { useState } from 'react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';

const dismissKey = (userId: number) => `schautrack.goalPromptDismissed.${userId}`;

function readDismissed(userId: number): boolean {
  try {
    return localStorage.getItem(dismissKey(userId)) === '1';
  } catch {
    return false;
  }
}

/**
 * Shown on your own dashboard while no calorie goal exists: without one the
 * ring has nothing to fill against and every day dot stays grey. The parent
 * stops rendering it once a goal is set; until then it can be dismissed, and
 * that choice is remembered per account on this device.
 */
export default function GoalPromptCard({ userId }: { userId: number }) {
  const { t } = useTranslation('dashboard');
  const [dismissed, setDismissed] = useState(() => readDismissed(userId));
  if (dismissed) return null;

  const dismiss = () => {
    setDismissed(true);
    try {
      localStorage.setItem(dismissKey(userId), '1');
    } catch {
      // Private mode / storage disabled: hiding it for this visit is enough.
    }
  };

  return (
    <section
      data-testid="goal-prompt"
      aria-labelledby="goal-prompt-title"
      className="surface flex flex-wrap items-center gap-3 border-[#0ea5e9]/30 p-4"
    >
      <div className="min-w-0 flex-1 basis-56">
        <h2 id="goal-prompt-title" className="font-display text-[15px] font-bold">{t('goalPrompt.title')}</h2>
        <p className="mt-1 text-[13px] leading-snug text-muted-foreground">{t('goalPrompt.body')}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button variant="ghost" size="sm" onClick={dismiss} data-testid="goal-prompt-dismiss">
          {t('goalPrompt.dismiss')}
        </Button>
        <Button size="sm" asChild>
          <Link to="/settings" data-testid="goal-prompt-cta">{t('goalPrompt.cta')}</Link>
        </Button>
      </div>
    </section>
  );
}
