import { useTranslation } from 'react-i18next';
import type { DailyStat } from '@/types';
import { cn } from '@/lib/utils';
import { formatDate } from '@/lib/format';
import { MACRO_LABELS, type MacroKey } from '@/lib/macros';
import { dotReasonDeviation } from '@/lib/goalFeedback';

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
  const statusLabel = statusLabels[status] || t('dayDot.status.none');
  // UTC on both sides: `date` is a calendar day, not an instant, so the
  // viewer's offset must not shift it to the day before.
  const day = new Date(`${date}T00:00:00Z`);
  const dateLabel = formatDate(day, undefined, { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
  const dayNumber = formatDate(day, undefined, { day: 'numeric', timeZone: 'UTC' });

  let reasonText = '';
  if (reason) {
    const metric = reason.metric === 'calories'
      ? t('entries.caloriesLabel')
      : MACRO_LABELS[reason.metric as MacroKey]?.label || reason.metric;
    const { direction, pct } = dotReasonDeviation(reason);
    reasonText = direction === 'over'
      ? t('dayDot.reason.over', { metric, pct })
      : t('dayDot.reason.under', { metric, pct });
  }

  return (
    <div className="flex flex-col items-center gap-1">
      <button
        type="button"
        className={cn(
          'size-[22px] rounded-md cursor-pointer transition-shadow border-0 p-0 shrink-0',
          STATUS_COLORS[status] || 'bg-white/[0.03]',
          isToday && 'ring-2 ring-primary',
          isSelected && 'ring-2 ring-foreground',
          !isToday && !isSelected && 'hover:ring-1 hover:ring-muted-foreground/40'
        )}
        onClick={onClick}
        title={`${dateLabel} — ${statusLabel}${reasonText ? `: ${reasonText}` : ''}`}
        // The ISO date leads so the label stays unique and machine-findable.
        aria-label={`${date}: ${statusLabel}${reasonText ? `, ${reasonText}` : ''}, ${dateLabel}`}
      />
      <span aria-hidden="true" className={cn('text-[9px] leading-none tabular-nums', isToday ? 'font-bold text-primary' : 'text-muted-foreground')}>
        {dayNumber}
      </span>
    </div>
  );
}
