import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Sheet } from '@/components/ui/Sheet';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));
const MINUTE_STEP = 5;
const MINUTES = Array.from({ length: 60 / MINUTE_STEP }, (_, i) => String(i * MINUTE_STEP).padStart(2, '0'));

function split(value: string): [string, string] {
  const [h = '', m = ''] = value.split(':');
  return [h, m];
}

/**
 * Pick a time by tapping, never by typing.
 *
 * A text field (and a native `<input type="time">`, which is a text field with
 * a picker bolted on) makes you type digits on a keyboard — on a phone that
 * means the numeric keypad covering half the screen to enter four characters.
 * Here the trigger opens a Sheet of hour and minute chips: two taps, no
 * keyboard, and every option is visible at once.
 *
 * Minutes step by 5 because that is the granularity a recurring reminder
 * actually needs. A value already stored off that grid keeps its own chip, so
 * opening the picker can never silently round someone's existing time.
 */
export function TimePicker({ value, onChange, onClear, label }: {
  value: string;
  onChange: (value: string) => void;
  onClear: () => void;
  label: string;
}) {
  const { t } = useTranslation('dashboard');
  const [open, setOpen] = useState(false);
  const [hour, minute] = split(value);

  const minutes = minute && !MINUTES.includes(minute) ? [...MINUTES, minute].sort() : MINUTES;

  // Picking either half alone still yields a complete HH:MM, so the value is
  // never a half-written time the API would reject.
  const pickHour = (h: string) => onChange(`${h}:${minute || '00'}`);
  const pickMinute = (m: string) => onChange(`${hour || '00'}:${m}`);

  const chip = (active: boolean) =>
    cn(
      'flex min-h-11 items-center justify-center rounded-[10px] border text-sm font-semibold tabular-nums transition-colors cursor-pointer',
      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50',
      active
        ? 'border-primary/60 bg-primary/15 text-primary'
        : 'border-white/10 bg-white/[0.04] text-muted-foreground hover:text-foreground hover:border-white/20',
    );

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label={label}
        data-testid="time-picker-trigger"
        className={cn(
          'flex min-h-11 items-center gap-2 rounded-md border border-input bg-muted/50 px-3 text-sm transition-colors cursor-pointer',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 hover:border-ring',
          value ? 'text-foreground font-semibold tabular-nums' : 'text-muted-foreground',
        )}
      >
        <svg className="size-4 shrink-0 opacity-70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="9" />
          <path d="M12 7v5l3 2" />
        </svg>
        {value || t('todos.setTimeButton')}
      </button>

      <Sheet open={open} onClose={() => setOpen(false)} title={label}>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('todos.hourLabel')}</span>
            <div role="group" aria-label={t('todos.hourLabel')} className="grid grid-cols-6 gap-1.5">
              {HOURS.map((h) => (
                <button key={h} type="button" aria-pressed={h === hour} onClick={() => pickHour(h)} className={chip(h === hour)}>
                  {h}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{t('todos.minuteLabel')}</span>
            <div role="group" aria-label={t('todos.minuteLabel')} className="grid grid-cols-6 gap-1.5">
              {minutes.map((m) => (
                <button key={m} type="button" aria-pressed={m === minute} onClick={() => pickMinute(m)} className={chip(m === minute)}>
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-2">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={!value}
              onClick={() => { onClear(); setOpen(false); }}
            >
              {t('todos.clearButton')}
            </Button>
            <Button type="button" size="sm" onClick={() => setOpen(false)}>{t('todos.doneButton')}</Button>
          </div>
        </div>
      </Sheet>
    </>
  );
}

export default TimePicker;
