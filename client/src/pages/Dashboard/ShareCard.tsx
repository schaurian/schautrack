import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { SharedView } from '@/types';
import { useDashboardStore } from '@/stores/dashboardStore';
import { updateLinkLabel } from '@/api/links';
import { useToastStore } from '@/stores/toastStore';
import DayDot from './DayDot';
import { cn } from '@/lib/utils';

interface Props {
  view: SharedView;
  todayStr: string;
  onDotClick: (date: string) => void;
  onSelect: () => void;
}

export default function ShareCard({ view, todayStr, onDotClick, onSelect }: Props) {
  const { t } = useTranslation('dashboard');
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
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      } catch (err) {
        useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('dashboard.toastUpdateLabelFailed'));
      }
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
    <div
      role="button"
      tabIndex={0}
      aria-pressed={isActive}
      aria-label={view.isSelf ? t('dashboard.viewOwnDayAriaLabel') : t('dashboard.viewFriendDayAriaLabel', { label: view.label })}
      onClick={onSelect}
      onKeyDown={(e) => {
        // Only self-trigger when the card itself is focused, so Enter/Escape
        // inside the label input (which bubbles up) doesn't also select.
        if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
          e.preventDefault();
          onSelect();
        }
      }}
      className="group cursor-pointer px-1 py-1.5"
    >
      <div className={cn(
        'mb-1 inline-flex items-center gap-1.5 border-b-2 pb-0.5 transition-colors',
        isActive ? 'border-primary' : 'border-transparent group-hover:border-white/15'
      )}>
        {editing && canEditLabel ? (
          <input
            className="bg-muted/50 border border-ring rounded px-1.5 py-0.5 text-sm text-foreground outline-none w-full"
            value={label}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => setLabel(e.target.value)}
            onBlur={handleSave}
            onKeyDown={handleKeyDown}
            maxLength={30}
            autoFocus
          />
        ) : canEditLabel ? (
          <button
            type="button"
            className="bg-transparent border border-transparent p-0 text-sm font-medium text-foreground text-left cursor-pointer hover:text-primary transition-colors"
            onClick={(e) => { e.stopPropagation(); setEditing(true); }}
            aria-label={t('dashboard.editLabelAriaLabel', { label: view.label })}
            title={t('dashboard.clickToEditLabelTitle')}
          >
            {view.label}
          </button>
        ) : (
          <span className="text-sm font-medium text-foreground">
            {view.label}
          </span>
        )}
      </div>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(18px,32px))] justify-between gap-x-3 gap-y-4 py-2 px-1">
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
