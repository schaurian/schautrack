import { useState } from 'react';
import type { SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import ShareCard from './ShareCard';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

const RANGE_PRESETS = [7, 14, 30, 60, 90, 120, 180];

interface Props {
  sharedViews: SharedView[];
  range: { start: string; end: string; days: number; preset: number | null };
  todayStr: string;
}

export default function Timeline({ sharedViews, range, todayStr }: Props) {
  const { rangePreset, setRange, selectDay, selectUser } = useDashboardStore();
  const [showCustom, setShowCustom] = useState(false);
  const [customStart, setCustomStart] = useState(range.start);
  const [customEnd, setCustomEnd] = useState(range.end);
  const isCustomActive = rangePreset === null;

  const handlePreset = (days: number) => {
    setShowCustom(false);
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

  const active = rangePreset || range.preset;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border">
        <h3 className="text-sm font-medium text-muted-foreground">Timeline</h3>
      </div>
      {/* Range selector */}
      <div className="flex flex-wrap gap-1.5 mx-4 mt-4 mb-4">
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
            {days}d
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
          Custom
        </button>
      </div>

      {/* Custom range inputs */}
      {showCustom && (
        <div className="flex flex-wrap items-center gap-2 mx-4 mb-4 p-3 rounded-md bg-surface border border-border">
          <input
            type="date"
            className="rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring"
            value={customStart}
            onChange={(e) => setCustomStart(e.target.value)}
          />
          <span className="text-xs text-muted-foreground font-medium">to</span>
          <input
            type="date"
            className="rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring"
            value={customEnd}
            onChange={(e) => setCustomEnd(e.target.value)}
          />
          <Button size="sm" onClick={handleCustomApply}>Apply</Button>
        </div>
      )}

      {/* Share cards */}
      <div className="flex flex-col gap-3 p-4 pt-0">
        {sharedViews.map((view) => (
          <ShareCard
            key={view.userId}
            view={view}
            todayStr={todayStr}
            onDotClick={(date) => handleDotClick(view, date)}
          />
        ))}
      </div>
    </div>
  );
}
