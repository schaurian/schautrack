import { useTranslation } from 'react-i18next';
import type { DailyStat } from '@/types';
import { cn } from '@/lib/utils';
import { formatDay } from '@/lib/format';
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
// date and the metric that decided the colour.
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
  const dateLabel = formatDay(date, 'short');

  let reasonText = '';
  if (reason) {
    const metric = reason.metric === 'calories'
      ? t('entries.caloriesLabel')
      : MACRO_LABELS[reason.metric as MacroKey]?.label || reason.metric;
    reasonText = reason.direction === 'over'
      ? t('dayDot.reason.over', { metric, pct: reason.pct })
      : t('dayDot.reason.under', { metric, pct: reason.pct });
  }

  // The button is the 44x44 hit area with the 22px coloured square centred in
  // it. ShareCard lays the buttons out edge to edge, so neighbouring hit areas
  // touch without overlapping.
  return (
    <button
      type="button"
      className="group/dot flex size-11 shrink-0 cursor-pointer items-center justify-center border-0 bg-transparent p-0"
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
    </button>
  );
}
