import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import { updateLinkLabel } from '@/api/links';
import DayDot from './DayDot';
import { cn } from '@/lib/utils';

interface Props {
  view: SharedView;
  todayStr: string;
  onDotClick: (date: string) => void;
}

export default function ShareCard({ view, todayStr, onDotClick }: Props) {
  const { selectedDate, currentUserId } = useDashboardStore();
  const queryClient = useQueryClient();
  const isActive = currentUserId === view.userId;
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState(view.label);

  const canEditLabel = !view.isSelf && view.linkId;

  const handleSave = async () => {
    if (!view.linkId) return;
    const trimmed = label.trim();
    if (trimmed && trimmed !== view.label) {
      try {
        await updateLinkLabel(view.linkId, trimmed);
        queryClient.refetchQueries({ queryKey: ['dashboard'] });
      } catch { /* ignore */ }
    } else {
      setLabel(view.label);
    }
    setEditing(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') { setEditing(false); setLabel(view.label); }
  };

  return (
    <div className={cn(
      'rounded-xl border p-4 transition-colors',
      isActive ? 'border-primary/40 bg-primary/[0.04]' : 'border-border bg-card'
    )}>
      <div className="mb-2">
        {editing && canEditLabel ? (
          <input
            className="bg-muted/50 border border-ring rounded px-1.5 py-0.5 text-sm text-foreground outline-none w-full"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            onBlur={handleSave}
            onKeyDown={handleKeyDown}
            maxLength={30}
            autoFocus
          />
        ) : (
          <span
            className={cn(
              'text-sm font-medium text-foreground',
              canEditLabel && 'cursor-pointer hover:text-primary transition-colors'
            )}
            onClick={canEditLabel ? () => setEditing(true) : undefined}
            title={canEditLabel ? 'Click to edit label' : undefined}
          >
            {view.label}
          </span>
        )}
      </div>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(18px,32px))] justify-between gap-x-3 gap-y-5 py-4 px-1">
        {view.dailyStats.map((stat) => (
          <DayDot
            key={stat.date}
            date={stat.date}
            status={stat.status}
            isToday={stat.date === todayStr}
            isSelected={isActive && stat.date === selectedDate}
            onClick={() => onDotClick(stat.date)}
          />
        ))}
      </div>
    </div>
  );
}
