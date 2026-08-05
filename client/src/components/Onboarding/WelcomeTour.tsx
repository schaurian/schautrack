import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/stores/authStore';
import { useOnboardingStore } from '@/stores/onboardingStore';
import { completeOnboarding } from '@/api/onboarding';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import { StreakArt, LogArt, DayArt, PlanArt, ShareArt } from './tourArt';

/**
 * First-run explainer. Opens by itself for an account that has never dismissed
 * it, and can be replayed from Settings.
 *
 * The progress indicator is the app's own activity ring rather than a row of
 * dots: the tour teaches "progress toward a goal is a ring that fills" while
 * you read about it, and each step advances the ring through one more macro
 * colour. That is the only flourish here — everything around it stays plain.
 */

interface Step {
  key: string;
  /** Ring colour for this step — walks the app's macro palette. */
  color: string;
  art: (props: { withAi: boolean }) => React.ReactElement;
}

const STEPS: Step[] = [
  { key: 'welcome', color: '#6d8cff', art: StreakArt },
  { key: 'log', color: '#22d3ee', art: LogArt },
  { key: 'day', color: '#a78bfa', art: DayArt },
  { key: 'plan', color: '#4ade80', art: PlanArt },
  { key: 'share', color: '#f472b6', art: ShareArt },
];

const RING_SIZE = 46;
const RING_R = 19;
const RING_C = 2 * Math.PI * RING_R;

export default function WelcomeTour() {
  const { t } = useTranslation();
  const user = useAuthStore((s) => s.user);
  const open = useOnboardingStore((s) => s.open);
  const start = useOnboardingStore((s) => s.start);
  const close = useOnboardingStore((s) => s.close);

  const [index, setIndex] = useState(0);
  // Direction of the last move, so the incoming panel slides the way the user
  // is travelling instead of always arriving from the same side.
  const [dir, setDir] = useState<1 | -1>(1);
  const panelRef = useRef<HTMLDivElement>(null);
  const nextRef = useRef<HTMLButtonElement>(null);
  // Guards the auto-open: /api/me still says onboardingCompleted=false until
  // the next fetch, so without this the tour would spring back the moment the
  // auth store refreshed after dismissal.
  const autoOpenedRef = useRef(false);

  useEffect(() => {
    if (autoOpenedRef.current || !user || user.onboardingCompleted) return;
    autoOpenedRef.current = true;
    start();
  }, [user, start]);

  // Every opening starts at step one — a replay from Settings is a fresh
  // watch, not a resume of wherever the last one was abandoned.
  useEffect(() => {
    if (!open) return;
    setIndex(0);
    setDir(1);
  }, [open]);

  const dismiss = useCallback(() => {
    close();
    autoOpenedRef.current = true;
    // Fire-and-forget: a failed write only means the tour offers itself again
    // on the next visit, which is better than blocking the dashboard behind a
    // retry dialog.
    completeOnboarding().catch(() => {});
  }, [close]);

  const go = useCallback((delta: 1 | -1) => {
    setDir(delta);
    setIndex((i) => Math.min(STEPS.length - 1, Math.max(0, i + delta)));
  }, []);

  // Escape closes; arrows step. Bound while open only.
  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    document.body.style.overflow = 'hidden';

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        dismiss();
        return;
      }
      if (e.key === 'ArrowRight') go(1);
      if (e.key === 'ArrowLeft') go(-1);
      if (e.key !== 'Tab') return;
      // Contain focus: this is a first-run modal over an app the user has not
      // seen yet, so tabbing out into the dashboard behind it is disorienting.
      const focusable = panelRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      );
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKey);
    nextRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKey);
      previouslyFocused?.focus?.();
    };
  }, [open, dismiss, go]);

  if (!open) return null;

  const step = STEPS[index];
  const isLast = index === STEPS.length - 1;
  const Art = step.art;
  const progress = (index + 1) / STEPS.length;

  // The photo-estimate route only exists when an AI key is configured. Without
  // one the logging step must drop the promise everywhere at once — copy,
  // heading and illustration — or it reads as "three ways" above a list of two.
  const aiAvailable = !!user?.hasAiKey || !!user?.hasGlobalAiKey;
  const suffix = step.key === 'log' && !aiAvailable ? 'NoAi' : '';
  const stepKey = (part: string) => `onboarding.steps.${step.key}.${part}${suffix}`;

  return createPortal(
    <div className="fixed inset-0 z-[300] flex items-end justify-center sm:items-center" data-testid="welcome-tour">
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-[3px] motion-safe:animate-in motion-safe:fade-in motion-safe:duration-200"
        onClick={dismiss}
        aria-hidden="true"
      />

      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="welcome-tour-title"
        className={cn(
          'surface relative w-full max-w-[480px] p-5 pb-[calc(1.25rem+env(safe-area-inset-bottom))]',
          'rounded-b-none sm:rounded-b-[22px] sm:pb-5',
          'motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-bottom-6 motion-safe:duration-300',
          'sm:motion-safe:zoom-in-95 sm:motion-safe:slide-in-from-bottom-2',
        )}
      >
        <header className="flex items-center gap-3">
          {/* Progress ring — the app's own instrument, filling as you advance. */}
          <div className="relative shrink-0" style={{ width: RING_SIZE, height: RING_SIZE }}>
            <svg width={RING_SIZE} height={RING_SIZE} className="-rotate-90" aria-hidden="true">
              <circle
                cx={RING_SIZE / 2}
                cy={RING_SIZE / 2}
                r={RING_R}
                fill="none"
                stroke="rgba(255,255,255,0.09)"
                strokeWidth={3}
              />
              <circle
                cx={RING_SIZE / 2}
                cy={RING_SIZE / 2}
                r={RING_R}
                fill="none"
                stroke={step.color}
                strokeWidth={3}
                strokeLinecap="round"
                strokeDasharray={RING_C}
                strokeDashoffset={RING_C * (1 - progress)}
                style={{
                  filter: `drop-shadow(0 0 4px ${step.color})`,
                  transition: 'stroke-dashoffset 0.5s cubic-bezier(0.22, 1, 0.36, 1), stroke 0.35s ease',
                }}
              />
            </svg>
            <span
              className="absolute inset-0 flex items-center justify-center font-display text-[13px] font-bold tabular-nums"
              style={{ color: step.color }}
            >
              {index + 1}
            </span>
          </div>

          <p className="min-w-0 flex-1 truncate font-display text-[11px] font-bold uppercase tracking-[0.16em] text-muted-foreground">
            {t(`onboarding.steps.${step.key}.eyebrow`)}
          </p>

          <button
            type="button"
            onClick={dismiss}
            aria-label={t('onboarding.close')}
            data-testid="welcome-tour-close"
            className="-mr-1 flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-[10px] border-0 bg-transparent text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0ea5e9]"
          >
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden="true">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </header>

        {/* The live region has to outlive the steps: the inner div is keyed on
            the index so React remounts it (that is what replays the entry
            animation), and a live region that is itself replaced announces
            nothing. */}
        <div aria-live="polite">
          <div
            key={index}
            className={cn(
              'motion-safe:animate-in motion-safe:fade-in motion-safe:duration-300',
              dir === 1 ? 'motion-safe:slide-in-from-right-4' : 'motion-safe:slide-in-from-left-4',
            )}
          >
            <div
              className="mt-4 aspect-[320/132] w-full overflow-hidden rounded-[14px] border border-white/[0.07] bg-black/25 p-3"
              role="img"
              aria-label={t(stepKey('art'))}
            >
              <Art withAi={aiAvailable} />
            </div>

            <h2 id="welcome-tour-title" className="mt-4 font-display text-[21px] font-bold leading-tight">
              {t(stepKey('title'))}
            </h2>
            <p className="mt-2 text-[14px] leading-relaxed text-muted-foreground">{t(stepKey('body'))}</p>
          </div>
        </div>

        <footer className="mt-5 flex items-center gap-2 border-t border-white/[0.07] pt-4">
          <p className="flex-1 text-[12px] tabular-nums text-muted-foreground/70">
            {t('onboarding.progress', { current: index + 1, total: STEPS.length })}
          </p>
          {index > 0 && (
            <Button variant="ghost" onClick={() => go(-1)}>
              {t('onboarding.back')}
            </Button>
          )}
          <Button
            ref={nextRef}
            onClick={() => (isLast ? dismiss() : go(1))}
            data-testid="welcome-tour-next"
          >
            {isLast ? t('onboarding.done') : t('onboarding.next')}
          </Button>
        </footer>
      </div>
    </div>,
    document.body,
  );
}
