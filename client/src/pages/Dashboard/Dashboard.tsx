import { useEffect } from 'react';
import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { getDashboard, getDayEntries } from '@/api/entries';
import { getWeightDay } from '@/api/weight';
import { useDashboardStore } from '@/stores/dashboardStore';
import TodayPanel from './TodayPanel';
import EntryForm from './EntryForm';
import Timeline from './Timeline';
import EntryList from './EntryList';
import WeightRow from './WeightRow';
import TodoList from './TodoList';
import NoteEditor from './NoteEditor';

export default function Dashboard() {
  const { user, isLoading: authLoading } = useRequireAuth();
  const { selectedDate, currentUserId, currentLabel, canEdit, rangePreset, rangeStart, rangeEnd, selectUser, selectDay } = useDashboardStore();
  const queryClient = useQueryClient();

  // Fetch dashboard data
  const { data: dashboard, isLoading } = useQuery({
    queryKey: ['dashboard', rangePreset, rangeStart, rangeEnd],
    queryFn: () => getDashboard({
      range: rangePreset || undefined,
      start: rangeStart || undefined,
      end: rangeEnd || undefined,
    }),
    enabled: !!user,
    placeholderData: keepPreviousData,
  });

  // Set self as current user on first load
  useEffect(() => {
    if (dashboard && !currentUserId) {
      selectUser(dashboard.user.id, 'You', true);
      selectDay(dashboard.selectedDate);
    }
  }, [dashboard, currentUserId, selectUser, selectDay]);

  const effectiveUserId = currentUserId || dashboard?.user.id;

  // Fetch entries for selected day
  const { data: dayData } = useQuery({
    queryKey: ['day-entries', effectiveUserId, selectedDate],
    queryFn: () => getDayEntries(effectiveUserId!, selectedDate),
    enabled: !!effectiveUserId && !!selectedDate,
    placeholderData: keepPreviousData,
  });

  // Fetch weight for selected day
  const { data: weightData } = useQuery({
    queryKey: ['weight', effectiveUserId, selectedDate],
    queryFn: () => getWeightDay(selectedDate, effectiveUserId),
    enabled: !!effectiveUserId && !!selectedDate,
    placeholderData: keepPreviousData,
  });

  if (authLoading || isLoading || !dashboard) {
    return <div className="flex items-center justify-center py-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  return (
    <div className="flex flex-col gap-2">
      <TodayPanel
        dailyGoal={dashboard.dailyGoal}
        todayTotal={dashboard.todayTotal}
        caloriesEnabled={dashboard.caloriesEnabled}
        calorieStatus={dashboard.calorieStatus}
        enabledMacros={dashboard.enabledMacros}
        macroGoals={dashboard.macroGoals}
        todayMacroTotals={dashboard.todayMacroTotals}
        macroStatuses={dashboard.macroStatuses}
        macroModes={dashboard.macroModes}
      />

      {canEdit && (
        <EntryForm
          selectedDate={selectedDate}
          caloriesEnabled={dashboard.caloriesEnabled}
          autoCalcCalories={dashboard.autoCalcCalories}
          enabledMacros={dashboard.enabledMacros}
          hasAiEnabled={dashboard.hasAiEnabled}
          aiUsage={dashboard.aiUsage}
          aiProviderName={dashboard.aiProviderName}
          barcodeEnabled={dashboard.barcodeEnabled}
          onSubmit={() => {
            queryClient.refetchQueries({ queryKey: ['dashboard'] });
            queryClient.refetchQueries({ queryKey: ['day-entries'] });
            queryClient.refetchQueries({ queryKey: ['weight'] });
          }}
        />
      )}

      <Timeline
        sharedViews={dashboard.sharedViews}
        range={dashboard.range}
        todayStr={dashboard.todayStr}
      />

      {effectiveUserId && selectedDate && (
        <TodoList
          date={selectedDate}
          userId={effectiveUserId}
          canEdit={canEdit}
          timezone={dashboard?.timeZone || 'UTC'}
        />
      )}

      {effectiveUserId && selectedDate && (
        <NoteEditor
          date={selectedDate}
          userId={effectiveUserId}
          canEdit={canEdit}
        />
      )}

      <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
        <div className="px-4 py-3 border-b-2 border-border flex items-center justify-between">
          <h3 className="text-sm font-medium text-muted-foreground">Entries</h3>
          <span className="text-sm text-muted-foreground">{selectedDate} &mdash; {currentLabel}</span>
        </div>

        <EntryList
          entries={dayData?.entries || []}
          canEdit={canEdit}
          enabledMacros={dashboard.enabledMacros}
          caloriesEnabled={dashboard.caloriesEnabled}
          autoCalcCalories={dashboard.autoCalcCalories}
        />
      </div>

      <WeightRow
        weightEntry={weightData?.entry || null}
        lastWeightEntry={weightData?.lastWeight || null}
        weightUnit={dashboard.weightUnit}
        canEdit={canEdit}
        selectedDate={selectedDate}
      />
    </div>
  );
}
