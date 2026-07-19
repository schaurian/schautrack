import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import ShareCard from './ShareCard';
import { Button } from '@/components/ui/Button';
import { SectionLabel } from '@/components/ui/SectionLabel';
import { cn } from '@/lib/utils';

const RANGE_PRESETS = [7, 14, 30, 60, 120];

interface Props {
  sharedViews: SharedView[];
  range: { start: string; end: string; days: number; preset: number | null };
  todayStr: string;
}

export default function Timeline({ sharedViews, range, todayStr }: Props) {
  const { t } = useTranslation('dashboard');
  const { rangePreset, setRange, selectDay, selectUser } = useDashboardStore();
  const [showRanges, setShowRanges] = useState(false);
  const [showCustom, setShowCustom] = useState(false);
  const [customStart, setCustomStart] = useState(range.start);
  const [customEnd, setCustomEnd] = useState(range.end);
  const isCustomActive = rangePreset === null;

  useEffect(() => {
    setCustomStart(range.start);
    setCustomEnd(range.end);
  }, [range.start, range.end]);

  const handlePreset = (days: number) => {
    setShowCustom(false);
    setShowRanges(false);
    setRange(days, '', '');
  };

  const handleCustomApply = () => {
    if (customStart && customEnd) {
      setRange(null, customStart, customEnd);
    }
  };

  const handleDotClick = (view: SharedView, date: string) => {
    selectUser(view.userId, view.label, view.isSelf);
    selectDay(date);
  };

  // Selecting the card (not a specific day) switches to that user, keeping the
  // current date. This is the only way to reach a friend who shares no
  // nutrition — their card renders no day-dots to click.
  const handleSelect = (view: SharedView) => {
    selectUser(view.userId, view.label, view.isSelf);
  };

  const active = rangePreset || range.preset;

  return (
    <section>
      <SectionLabel
        right={
          <button
            type="button"
            className="cursor-pointer rounded-md border border-transparent bg-transparent px-2 py-1 text-xs font-bold text-primary transition-colors hover:bg-surface-hover"
            onClick={() => setShowRanges(!showRanges)}
            aria-expanded={showRanges}
          >
            {t('dashboard.rangeDays', { count: range.days })} ▾
          </button>
        }
      >
        {t('dashboard.timelineTitle')}
      </SectionLabel>
      {/* Range selector */}
      {showRanges && (
      <div className="flex flex-wrap gap-1.5 px-1 pb-3">
        {RANGE_PRESETS.map((days) => (
          <button
            key={days}
            type="button"
            className={cn(
              'rounded-md px-3 py-1.5 text-xs font-bold border transition-colors cursor-pointer',
              active === days
                ? 'bg-primary/15 border-primary/60 text-primary'
                : 'bg-surface border-border text-muted-foreground hover:border-primary/30 hover:text-foreground'
            )}
            onClick={() => handlePreset(days)}
          >
            {t('dashboard.rangeDays', { count: days })}
          </button>
        ))}
        <button
          type="button"
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-bold border transition-colors cursor-pointer',
            (isCustomActive || showCustom)
              ? 'bg-primary/15 border-primary/60 text-primary'
              : 'bg-surface border-border text-muted-foreground hover:border-primary/30 hover:text-foreground'
          )}
          onClick={() => setShowCustom(!showCustom)}
        >
          {t('dashboard.customRangeButton')}
        </button>
      </div>
      )}

      {/* Custom range inputs */}
      {showCustom && (
        <div className="flex flex-wrap items-center gap-2 mx-1 mb-3 p-3 rounded-md bg-surface border border-border">
          <input
            type="date"
            className="rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring"
            value={customStart}
            onChange={(e) => setCustomStart(e.target.value)}
          />
          <span className="text-xs text-muted-foreground font-medium">{t('dashboard.customRangeTo')}</span>
          <input
            type="date"
            className="rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring"
            value={customEnd}
            onChange={(e) => setCustomEnd(e.target.value)}
          />
          <Button size="sm" onClick={handleCustomApply}>{t('dashboard.customRangeApply')}</Button>
        </div>
      )}

      {/* Share cards */}
      <div className="flex flex-col gap-2 px-0">
        {sharedViews.map((view) => (
          <ShareCard
            key={view.userId}
            view={view}
            todayStr={todayStr}
            onDotClick={(date) => handleDotClick(view, date)}
            onSelect={() => handleSelect(view)}
          />
        ))}
      </div>
    </section>
  );
}
