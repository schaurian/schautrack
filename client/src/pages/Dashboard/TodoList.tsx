import { useState, useEffect, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getTodos, getTodosDay, toggleTodo, createTodo, updateTodo, deleteTodo } from '@/api/todos';
import { useToastStore } from '@/stores/toastStore';
import { Button } from '@/components/ui/Button';
import type { Todo, TodoDay } from '@/types';

const DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

function formatTimeDigits(digits: string): string {
  if (digits.length <= 2) return digits;
  return digits.slice(0, 2) + ':' + digits.slice(2, 4);
}

function toTimeValue(digits: string): string {
  if (!digits) return '';
  const h = digits.slice(0, 2).padEnd(2, '0');
  const m = digits.length >= 3 ? digits.slice(2, 4).padEnd(2, '0') : '00';
  return `${h}:${m}`;
}

function TimeInput({ value, onChange, onClear }: { value: string; onChange: (v: string) => void; onClear: () => void }) {
  // value is HH:MM or '', digits is raw digits only
  const digits = value.replace(':', '');

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value.replace(/\D/g, '').slice(0, 4);
    onChange(raw ? formatTimeDigits(raw) : '');
  };

  const handleBlur = () => {
    if (digits) onChange(toTimeValue(digits));
  };

  return (
    <span className="relative flex items-center gap-2">
      <input
        type="text"
        inputMode="numeric"
        value={value}
        onChange={handleChange}
        onBlur={handleBlur}
        placeholder="HH:MM"
        maxLength={5}
        className="w-24 rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring pr-7"
      />
      <span className="absolute right-2 text-[10px] text-muted-foreground/60 pointer-events-none">🕑</span>
      {value && (
        <Button type="button" size="sm" variant="ghost" onClick={onClear}>Clear</Button>
      )}
    </span>
  );
}
const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  date: string;
  userId: number;
  canEdit: boolean;
  timezone: string;
}

type TodoState = 'completed' | 'overdue' | 'upcoming';

function getTodayStr(timezone: string): string {
  return new Date().toLocaleDateString('en-CA', { timeZone: timezone });
}

function getCurrentTime(timezone: string): string {
  return new Date().toLocaleTimeString('en-GB', { timeZone: timezone, hour: '2-digit', minute: '2-digit', hour12: false });
}

function getTodoState(todo: TodoDay, viewDate: string, todayStr: string, currentTime: string): TodoState {
  if (todo.completed) return 'completed';
  if (viewDate < todayStr) return 'overdue';
  if (viewDate > todayStr) return 'upcoming';
  // Viewing today
  if (!todo.time_of_day) return 'overdue';
  return todo.time_of_day <= currentTime ? 'overdue' : 'upcoming';
}

function getMissedLabel(missedSince: string | undefined, viewDate: string): string | null {
  if (!missedSince) return null;
  const missed = new Date(missedSince + 'T12:00:00');
  const view = new Date(viewDate + 'T12:00:00');
  const diffDays = Math.round((view.getTime() - missed.getTime()) / 86400000);
  if (diffDays <= 0) return null;
  if (diffDays === 1) return 'Yesterday';
  return `${diffDays}d`;
}

function ScheduleEditor({ schedule, onChange }: { schedule: Todo['schedule']; onChange: (s: Todo['schedule']) => void }) {
  const isDaily = schedule.type === 'daily';
  const days = schedule.type === 'weekdays' ? schedule.days : [];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
          <input type="radio" checked={isDaily} onChange={() => onChange({ type: 'daily' })} className="accent-primary" />
          Daily
        </label>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
          <input type="radio" checked={!isDaily} onChange={() => onChange({ type: 'weekdays', days: days.length > 0 ? days : [1, 2, 3, 4, 5] })} className="accent-primary" />
          Specific days
        </label>
      </div>
      {!isDaily && (
        <div className="flex gap-1 flex-wrap">
          {DAY_LABELS.map((label, i) => {
            const day = i + 1;
            const active = days.includes(day);
            return (
              <button
                key={day}
                type="button"
                onClick={() => {
                  const next = active ? days.filter((d) => d !== day) : [...days, day].sort();
                  if (next.length > 0) onChange({ type: 'weekdays', days: next });
                }}
                className={`px-2 py-1 text-xs rounded-md border transition-colors ${
                  active ? 'border-primary bg-primary/10 text-primary' : 'border-input bg-muted/50 text-muted-foreground hover:border-ring'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function formatSchedule(schedule: Todo['schedule']) {
  if (schedule.type === 'daily') return 'Daily';
  return schedule.days.map((d) => DAY_LABELS[d - 1]).join(', ');
}

export default function TodoList({ date, userId, canEdit, timezone }: Props) {
  const queryClient = useQueryClient();
  const [managing, setManaging] = useState(false);
  const [addOnOpen, setAddOnOpen] = useState(false);
  const [tick, setTick] = useState(0);

  const todayStr = useMemo(() => getTodayStr(timezone), [timezone, tick]);
  const currentTime = useMemo(() => getCurrentTime(timezone), [timezone, tick]);
  const isToday = date === todayStr;

  // Re-render every 60s when viewing today so overdue/upcoming flips as time passes
  useEffect(() => {
    if (!isToday) return;
    const interval = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(interval);
  }, [isToday]);

  const { data } = useQuery({
    queryKey: ['todos-day', userId, date],
    queryFn: () => getTodosDay(date, userId),
    enabled: !!date && !!userId,
  });

  if (!data?.enabled) return null;

  const handleToggle = async (todo: TodoDay) => {
    if (!canEdit) return;
    queryClient.setQueryData(
      ['todos-day', userId, date],
      (old: typeof data | undefined) => {
        if (!old) return old;
        return {
          ...old,
          todos: old.todos.map((a: TodoDay) =>
            a.id === todo.id ? { ...a, completed: !a.completed, missed_since: undefined, streak: a.completed ? Math.max(0, a.streak - 1) : a.streak + 1 } : a
          ),
        };
      }
    );
    try {
      await toggleTodo(todo.id, date);
      queryClient.refetchQueries({ queryKey: ['todos-day', userId, date] });
    } catch {
      queryClient.refetchQueries({ queryKey: ['todos-day', userId, date] });
    }
  };

  const completed = data.todos.filter((a) => a.completed).length;
  const total = data.todos.length;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Todos</h3>
        <div className="flex items-center gap-2">
          {total > 0 && <span className="text-xs text-muted-foreground">{completed}/{total}</span>}
          {canEdit && (
            <button
              type="button"
              onClick={() => setManaging(!managing)}
              className={`rounded-md px-2.5 py-0.5 text-xs font-medium border transition-colors cursor-pointer ${
                managing
                  ? 'border-primary/30 bg-primary/10 text-primary'
                  : 'border-border bg-muted/30 text-muted-foreground hover:border-ring hover:text-foreground'
              }`}
            >
              {managing ? 'Done' : 'Edit'}
            </button>
          )}
        </div>
      </div>

      {managing ? (
        <TodoManager onClose={() => setManaging(false)} initialAdd={addOnOpen} onAddShown={() => setAddOnOpen(false)} />
      ) : (
        <>
          {data.todos.length > 0 ? (
            <ul className="divide-y divide-border">
              {data.todos.map((todo) => {
                const state = getTodoState(todo, date, todayStr, currentTime);
                const missedLabel = getMissedLabel(todo.missed_since, date);
                const nameClass = {
                  completed: 'text-green-400 line-through',
                  overdue: 'text-red-400',
                  upcoming: 'text-muted-foreground',
                }[state];
                const checkboxClass = {
                  completed: 'border-green-500 bg-green-500 text-white',
                  overdue: 'border-red-400 bg-muted/50 hover:border-red-500',
                  upcoming: 'border-input bg-muted/50 hover:border-ring',
                }[state];

                return (
                  <li key={todo.id} className="flex items-center gap-3 px-4 py-2.5">
                    <div className="flex-1 min-w-0">
                      <span className={`text-sm ${nameClass}`}>
                        {todo.name}
                      </span>
                      {missedLabel && (
                        <span className="ml-1.5 text-[10px] font-medium text-red-400 bg-red-500/10 rounded px-1 py-0.5">
                          {missedLabel}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {todo.time_of_day && (
                        <span className="text-xs text-muted-foreground">{todo.time_of_day}</span>
                      )}
                      {todo.streak > 1 && (
                        <span className="text-xs text-primary font-medium">{todo.streak}d</span>
                      )}
                      <button
                        type="button"
                        onClick={() => handleToggle(todo)}
                        disabled={!canEdit}
                        className={`flex size-5 shrink-0 items-center justify-center rounded border transition-colors ${checkboxClass} ${!canEdit ? 'cursor-default' : 'cursor-pointer'}`}
                        aria-label={`${todo.completed ? 'Uncheck' : 'Check'} ${todo.name}`}
                      >
                        {todo.completed && (
                          <svg className="size-3" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M2 6l3 3 5-5" />
                          </svg>
                        )}
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="px-4 py-3 flex justify-end">
              <button
                type="button"
                onClick={() => { setManaging(true); setAddOnOpen(true); }}
                className="rounded-md px-4 py-2 text-sm font-semibold text-primary border border-primary/30 bg-primary/10 hover:bg-primary/20 transition-colors cursor-pointer"
              >
                Add a todo
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function TodoManager({ onClose, initialAdd, onAddShown }: { onClose: () => void; initialAdd?: boolean; onAddShown?: () => void }) {
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);
  const { data } = useQuery({ queryKey: ['todos'], queryFn: getTodos });

  const [newName, setNewName] = useState('');
  const [newSchedule, setNewSchedule] = useState<Todo['schedule']>({ type: 'daily' });
  const [newTime, setNewTime] = useState('');
  const [creating, setCreating] = useState(false);
  const [showAddForm, setShowAddForm] = useState(!!initialAdd);

  useEffect(() => {
    if (initialAdd) onAddShown?.();
  }, [initialAdd, onAddShown]);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editName, setEditName] = useState('');
  const [editSchedule, setEditSchedule] = useState<Todo['schedule']>({ type: 'daily' });
  const [editTime, setEditTime] = useState('');
  const [saving, setSaving] = useState(false);

  const refresh = () => {
    queryClient.refetchQueries({ queryKey: ['todos'] });
    queryClient.refetchQueries({ queryKey: ['todos-day'] });
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    setCreating(true);
    try {
      await createTodo({ name: newName.trim(), schedule: newSchedule, time_of_day: newTime || null });
      setNewName('');
      setNewSchedule({ type: 'daily' });
      setNewTime('');
      setShowAddForm(false);
      refresh();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to create todo');
    }
    setCreating(false);
  };

  const startEdit = (todo: Todo) => {
    setEditingId(todo.id);
    setEditName(todo.name);
    setEditSchedule(todo.schedule);
    setEditTime(todo.time_of_day || '');
  };

  const handleUpdate = async (id: number) => {
    if (!editName.trim()) return;
    setSaving(true);
    try {
      await updateTodo(id, { name: editName.trim(), schedule: editSchedule, time_of_day: editTime || null });
      setEditingId(null);
      refresh();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to update todo');
    }
    setSaving(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteTodo(id);
      refresh();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to delete todo');
    }
  };

  const todos = data?.todos || [];

  return (
    <div className="flex flex-col">
      {todos.length > 0 && (
        <ul className="divide-y divide-border">
          {todos.map((todo) => (
            <li key={todo.id}>
              {editingId === todo.id ? (
                <div className="flex flex-col gap-2 p-3 bg-muted/20">
                  <input value={editName} onChange={(e) => setEditName(e.target.value)} className={inputClass} maxLength={100} autoFocus />
                  <ScheduleEditor schedule={editSchedule} onChange={setEditSchedule} />
                  <div className="flex items-center gap-2">
                    <TimeInput value={editTime} onChange={setEditTime} onClear={() => setEditTime('')} />
                  </div>
                  <div className="flex gap-2 justify-end">
                    <Button type="button" size="sm" variant="ghost" onClick={() => setEditingId(null)}>Cancel</Button>
                    <Button type="button" size="sm" onClick={() => handleUpdate(todo.id)} disabled={saving} loading={saving}>Save</Button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/10 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-foreground truncate">{todo.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {todo.time_of_day && <span>{todo.time_of_day} &middot; </span>}
                      {formatSchedule(todo.schedule)}
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <Button type="button" size="sm" variant="outline" onClick={() => startEdit(todo)}>Edit</Button>
                    <Button type="button" size="sm" variant="destructive" onClick={() => handleDelete(todo.id)}>Remove</Button>
                  </div>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      <div className="p-3 border-t border-border">
        {showAddForm ? (
          <form onSubmit={handleCreate} className="flex flex-col gap-2">
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Todo name" className={inputClass} maxLength={100} autoFocus />
            <ScheduleEditor schedule={newSchedule} onChange={setNewSchedule} />
            <div className="flex items-center gap-2">
              <TimeInput value={newTime} onChange={setNewTime} onClear={() => setNewTime('')} />
            </div>
            <div className="flex gap-2 justify-end">
              <Button type="button" size="sm" variant="ghost" onClick={() => { setShowAddForm(false); setNewName(''); setNewTime(''); setNewSchedule({ type: 'daily' }); }}>Cancel</Button>
              <Button type="submit" size="sm" disabled={!newName.trim() || creating} loading={creating}>Add</Button>
            </div>
          </form>
        ) : (
          <div className="flex items-center justify-between">
            <Button type="button" size="sm" variant="ghost" onClick={onClose}>Done</Button>
            <Button type="button" size="sm" onClick={() => setShowAddForm(true)}>Add todo</Button>
          </div>
        )}
      </div>
    </div>
  );
}
