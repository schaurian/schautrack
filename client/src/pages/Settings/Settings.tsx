import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRequireAuth } from '@/hooks/useAuth';
import { useAuthStore } from '@/stores/authStore';
import { getSettings } from '@/api/settings';
import { Alert } from '@/components/ui/Alert';
import { QueryError } from '@/components/ui/QueryError';
import MacroSettings from './MacroSettings';
import PreferencesSettings from './PreferencesSettings';
import AISettings from './AISettings';
import LinkSettings from './LinkSettings';
import TodoSettings from './TodoSettings';
import NoteSettings from './NoteSettings';
import BodyFatSettings from './BodyFatSettings';
import SavedFoodsSettings from './SavedFoodsSettings';

/**
 * Tracking preferences — the things tuned while using the app.
 *
 * Identity, credentials and data ownership live on /account, its own sibling
 * nav item in both the sidebar and the bottom tab bar. Keeping them apart stops
 * calorie goals — the most-used setting in a calorie tracker — from sitting
 * above five auth sections a user configures once.
 *
 * LinkSettings stays here: sharing your log with a friend is a tracking
 * feature, and its pending-request badge belongs on a nav item you look at.
 */
export default function Settings() {
  const { isLoading: authLoading } = useRequireAuth();
  const queryClient = useQueryClient();

  const { data, isLoading, isError, error, isFetching, refetch } = useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  });

  if (isError && !data) {
    return <QueryError error={error} onRetry={() => refetch()} retrying={isFetching} />;
  }

  if (authLoading || isLoading || !data) {
    return <div className="flex items-center justify-center p-12"><div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" /></div>;
  }

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['settings'] });
    // The current user lives in the auth store, not a query — re-fetch it
    // so changes (macros, preferences, …) propagate app-wide.
    useAuthStore.getState().fetchUser();
  };

  return (
    <div className="flex flex-col gap-4" data-testid="settings-page">
      {data.linkFeedback && <Alert type={data.linkFeedback.type as 'success' | 'error'} message={data.linkFeedback.message} />}
      {data.aiFeedback && <Alert type={data.aiFeedback.type as 'success' | 'error'} message={data.aiFeedback.message} />}

      {/* Single flat column — grouped native-settings style. */}
      <div className="flex flex-col gap-3">
        <div className="break-inside-avoid">
          <MacroSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <PreferencesSettings user={data.user} timezones={data.timezones} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <TodoSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <NoteSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <BodyFatSettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <SavedFoodsSettings />
        </div>
        <div className="break-inside-avoid">
          <AISettings user={data.user} onSave={refresh} />
        </div>
        <div className="break-inside-avoid">
          <LinkSettings
            incomingRequests={data.incomingRequests}
            outgoingRequests={data.outgoingRequests}
            acceptedLinks={data.acceptedLinks}
            availableSlots={data.availableSlots}
            onUpdate={refresh}
          />
        </div>
      </div>
    </div>
  );
}
