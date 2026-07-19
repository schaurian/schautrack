import { useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert } from './Alert';
import { Button } from './Button';

function subscribe(callback: () => void) {
  window.addEventListener('online', callback);
  window.addEventListener('offline', callback);
  return () => {
    window.removeEventListener('online', callback);
    window.removeEventListener('offline', callback);
  };
}

function getOnline() {
  return navigator.onLine;
}

interface QueryErrorProps {
  /** The error thrown by the failed query (used for its message when online). */
  error?: unknown;
  /** Re-run the failed query. */
  onRetry: () => void;
  /** Whether a retry is currently in flight (drives the button spinner). */
  retrying?: boolean;
}

/**
 * Full-page fallback for a query whose initial load failed, so pages don't hang
 * on an infinite spinner when the device is offline or the server errors.
 * Shows an offline hint via navigator.onLine and a Retry button.
 */
export function QueryError({ error, onRetry, retrying }: QueryErrorProps) {
  const { t } = useTranslation('common');
  // Re-render when connectivity changes so the hint stays accurate.
  const online = useSyncExternalStore(subscribe, getOnline, () => true);
  const message = online
    ? error instanceof Error && error.message
      ? error.message
      : t('queryError.generic')
    : t('queryError.offline');

  return (
    <div className="flex flex-col items-center gap-4 py-12 text-center">
      <Alert type="error" message={message} className="max-w-sm" />
      <Button variant="outline" onClick={onRetry} loading={retrying}>
        {t('queryError.retry')}
      </Button>
    </div>
  );
}

export default QueryError;
