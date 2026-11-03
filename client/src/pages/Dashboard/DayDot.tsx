import { useTranslation } from 'react-i18next';
import type { DailyStat } from '@/types';
import { cn } from '@/lib/utils';
import { formatDate, formatDay } from '@/lib/format';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';

interface Props {
  date: string;
  status: string;
  reason?: DailyStat['reason'];
  isToday: boolean;
  isSelected: boolean;
  onClick: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  under: 'bg-success',
  over: 'bg-warning',
  over_threshold: 'bg-destructive',
  zero: 'bg-white/[0.06]',
  none: 'bg-white/[0.03]',
};

// A dot takes the worst status across calories and every macro, so it can be
// red while the calorie ring is only amber. The tooltip and label name the
// date and the metric that decided the colour; the day number under the dot
// keeps the direction readable once 14 dots wrap into two rows on a phone.
export default function DayDot({ date, status, reason, isToday, isSelected, onClick }: Props) {
  const { t } = useTranslation('dashboard');
  const statusLabels: Record<string, string> = {
    under: t('dayDot.status.under'),
    over: t('dayDot.status.over'),
    over_threshold: t('dayDot.status.overThreshold'),
    zero: t('dayDot.status.zero'),
    none: t('dayDot.status.none'),
  };
  // A missed target colours the dot like an overshoot does, but calling it
  // "over goal" next to "10% under target" contradicts itself.
  const statusLabel = reason?.direction === 'under'
    ? t('dayDot.status.missedTarget')
    : statusLabels[status] || t('dayDot.status.none');
  // The shared short day style (same as the date pill and entries header).
  // The day number: UTC on both sides, since `date` is a calendar day, not an
  // instant, and the viewer's offset must not shift it to the day before.
  const day = new Date(`${date}T00:00:00Z`);
  const dateLabel = formatDay(date, 'short');
  const dayNumber = formatDate(day, undefined, { day: 'numeric', timeZone: 'UTC' });

  let reasonText = '';
  if (reason) {
    const metric = reason.metric === 'calories'
      ? t('entries.caloriesLabel')
      : MACRO_LABELS[reason.metric as MacroKey]?.label || reason.metric;
    reasonText = reason.direction === 'over'
      ? t('dayDot.reason.over', { metric, pct: reason.pct })
      : t('dayDot.reason.under', { metric, pct: reason.pct });
  }

  // The button is the 44x44 hit area. Inside it, stacked and centred: the 22px
  // coloured square, then its day number 2px below. ShareCard lays the buttons
  // out edge to edge, so neighbouring hit areas touch without overlapping, and
  // each number sits inside its own dot's button rather than between rows.
  return (
    <button
      type="button"
      className="group/dot flex size-11 shrink-0 cursor-pointer flex-col items-center justify-center gap-0.5 border-0 bg-transparent p-0"
      onClick={onClick}
      title={`${dateLabel} — ${statusLabel}${reasonText ? `: ${reasonText}` : ''}`}
      // The ISO date leads so the label stays unique and machine-findable.
      aria-label={`${date}: ${statusLabel}${reasonText ? `, ${reasonText}` : ''}, ${dateLabel}`}
    >
      <span
        aria-hidden="true"
        className={cn(
          'size-[22px] shrink-0 rounded-md transition-shadow',
          STATUS_COLORS[status] || 'bg-white/[0.03]',
          isToday && 'ring-2 ring-primary',
          isSelected && 'ring-2 ring-foreground',
          !isToday && !isSelected && 'group-hover/dot:ring-1 group-hover/dot:ring-muted-foreground/40'
        )}
      />
      <span aria-hidden="true" className={cn('text-[9px] leading-none tabular-nums', isToday ? 'font-bold text-primary' : 'text-muted-foreground')}>
        {dayNumber}
      </span>
    </button>
  );
}
