import { useState } from 'react';
import { toggleNotesEnabled } from '@/api/notes';
import type { User } from '@/types';
import { Card } from '@/components/ui/Card';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  user: User;
  onSave: () => void;
}

export default function NoteSettings({ user, onSave }: Props) {
  const addToast = useToastStore((s) => s.addToast);
  const [enabled, setEnabled] = useState(user.notesEnabled);
  const [toggling, setToggling] = useState(false);

  const handleToggle = async () => {
    setToggling(true);
    try {
      const newEnabled = !enabled;
      await toggleNotesEnabled(newEnabled);
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
        <h3 className="text-sm font-semibold">Daily Notes</h3>
        <button
          type="button"
          onClick={handleToggle}
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
        <p className="text-xs text-muted-foreground mt-2">Write a daily note on the dashboard for any date.</p>
      )}
    </Card>
  );
}
