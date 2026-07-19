import { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { getNote, saveNote } from '@/api/notes';
import { useToastStore } from '@/stores/toastStore';
import { SectionLabel } from '@/components/ui/SectionLabel';

interface Props {
  date: string;
  userId: number;
  canEdit: boolean;
}

export default function NoteEditor({ date, userId, canEdit }: Props) {
  const { t } = useTranslation('dashboard');
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastSavedRef = useRef('');
  // Track editing state so a refetch (SSE note-change, window refocus, …)
  // can't clobber keystrokes typed during the save/refetch window.
  const dirtyRef = useRef(false);
  const focusedRef = useRef(false);
  const valueRef = useRef('');

  const { data } = useQuery({
    queryKey: ['note', userId, date],
    queryFn: () => getNote(date, userId),
    enabled: !!date && !!userId,
  });

  useEffect(() => {
    // Switching day/user is a hard context switch — discard local edit
    // state so the incoming note content always syncs. Any pending edit
    // was already flushed by the blur that preceded the switch.
    dirtyRef.current = false;
    if (timerRef.current) clearTimeout(timerRef.current);
  }, [date, userId]);

  useEffect(() => {
    // Only sync server content into local state while the user isn't
    // editing; otherwise in-progress typing would be silently replaced.
    if (data && !dirtyRef.current && !focusedRef.current) {
      setValue(data.content || '');
      valueRef.current = data.content || '';
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
      // Only mark clean if nothing was typed while the save was in flight.
      if (valueRef.current === content) dirtyRef.current = false;
      setSaved(true);
      if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
      savedTimerRef.current = setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      useToastStore.getState().addToast('error', err instanceof Error ? err.message : t('notes.toastSaveFailed'));
    }
    setSaving(false);
  }, [date, t]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    setValue(newValue);
    valueRef.current = newValue;
    dirtyRef.current = true;
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => doSave(newValue), 1000);
  };

  const handleFocus = () => {
    focusedRef.current = true;
  };

  const handleBlur = () => {
    focusedRef.current = false;
    if (timerRef.current) clearTimeout(timerRef.current);
    doSave(value);
  };

  if (!data?.enabled) return null;

  return (
    <section className="surface p-4">
      <SectionLabel
        right={
          <div className="flex items-center gap-2">
            {saving && <span className="text-xs text-muted-foreground animate-pulse">{t('notes.savingIndicator')}</span>}
            {!saving && saved && <span className="text-xs text-green-400">{t('notes.savedIndicator')}</span>}
            {canEdit && <span className={`text-xs ${value.length > 9500 ? 'text-destructive' : 'text-muted-foreground'}`}>{t('notes.charCount', { count: value.length })}</span>}
          </div>
        }
      >
        {t('notes.sectionTitle')}
      </SectionLabel>
      <div className="px-1 py-1">
        <textarea
          value={value}
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          disabled={!canEdit}
          maxLength={10000}
          placeholder={canEdit ? t('notes.placeholder') : ''}
          rows={3}
          className="w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring resize-y min-h-[60px] disabled:opacity-60 disabled:cursor-default"
        />
      </div>
    </section>
  );
}
