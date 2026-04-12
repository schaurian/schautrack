import { useState } from 'react';
import { toggleTodosEnabled } from '@/api/todos';
import type { User } from '@/types';
import { Card } from '@/components/ui/Card';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  user: User;
  onSave: () => void;
}

export default function TodoSettings({ user, onSave }: Props) {
  const addToast = useToastStore((s) => s.addToast);
  const [enabled, setEnabled] = useState(user.todosEnabled);
  const [toggling, setToggling] = useState(false);

  const handleToggleEnabled = async () => {
    setToggling(true);
    try {
      const newEnabled = !enabled;
      await toggleTodosEnabled(newEnabled);
      setEnabled(newEnabled);
      onSave();
    } catch {
      addToast('error', 'Failed to update setting');
    }
    setToggling(false);
  };

  return (
    <Card>
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Todos</h3>
        <button
          type="button"
          onClick={handleToggleEnabled}
          disabled={toggling}
          className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
            enabled ? 'bg-primary' : 'bg-muted'
          } ${toggling ? 'opacity-50' : ''}`}
        >
          <span className={`pointer-events-none inline-block size-4 rounded-full bg-white shadow-sm transition-transform ${
            enabled ? 'translate-x-4' : 'translate-x-0'
          }`} />
        </button>
      </div>
      {enabled && (
        <p className="text-xs text-muted-foreground mt-2">Manage your todos on the dashboard.</p>
      )}
    </Card>
  );
}
