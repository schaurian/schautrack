import { useState, useEffect, useRef, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getNote, saveNote } from '@/api/notes';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  date: string;
  userId: number;
  canEdit: boolean;
}

export default function NoteEditor({ date, userId, canEdit }: Props) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastSavedRef = useRef('');

  const { data } = useQuery({
    queryKey: ['note', userId, date],
    queryFn: () => getNote(date, userId),
    enabled: !!date && !!userId,
  });

  useEffect(() => {
    if (data) {
      setValue(data.content || '');
      lastSavedRef.current = data.content || '';
    }
  }, [data]);

  const doSave = useCallback(async (content: string) => {
    if (content === lastSavedRef.current) return;
    setSaving(true);
    setSaved(false);
    try {
      await saveNote(date, content);
      lastSavedRef.current = content;
      queryClient.refetchQueries({ queryKey: ['note'] });
      setSaved(true);
      if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
      savedTimerRef.current = setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : 'Failed to save note');
    }
    setSaving(false);
  }, [date, queryClient]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    setValue(newValue);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => doSave(newValue), 1000);
  };

  const handleBlur = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    doSave(value);
  };

  if (!data?.enabled) return null;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Notes</h3>
        <div className="flex items-center gap-2">
          {saving && <span className="text-xs text-muted-foreground animate-pulse">Saving...</span>}
          {!saving && saved && <span className="text-xs text-green-400">Saved</span>}
          {canEdit && <span className={`text-xs ${value.length > 9500 ? 'text-destructive' : 'text-muted-foreground'}`}>{value.length}/10000</span>}
        </div>
      </div>
      <div className="p-3">
        <textarea
          value={value}
          onChange={handleChange}
          onBlur={handleBlur}
          disabled={!canEdit}
          maxLength={10000}
          placeholder={canEdit ? 'Write a note for this day...' : ''}
          rows={3}
          className="w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring resize-y min-h-[60px] disabled:opacity-60 disabled:cursor-default"
        />
      </div>
    </div>
  );
}
