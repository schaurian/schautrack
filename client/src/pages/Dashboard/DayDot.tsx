import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

interface Props {
  date: string;
  status: string;
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

export default function DayDot({ date, status, isToday, isSelected, onClick }: Props) {
  const { t } = useTranslation('dashboard');
  const statusLabels: Record<string, string> = {
    under: t('dayDot.status.under'),
    over: t('dayDot.status.over'),
    over_threshold: t('dayDot.status.overThreshold'),
    zero: t('dayDot.status.zero'),
    none: t('dayDot.status.none'),
  };
  return (
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
      title={date}
      aria-label={`${date}: ${statusLabels[status] || t('dayDot.status.none')}`}
    />
  );
}
