import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getTodos, getTodosDay, toggleTodo, createTodo, updateTodo, deleteTodo } from '@/api/todos';
import type { Todo, TodoDay } from '@/types';

const DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const inputClass = 'w-full rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';
const timeInputClass = 'w-24 rounded-md border border-input bg-muted/50 px-2.5 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring';

interface Props {
  date: string;
  userId: number;
  canEdit: boolean;
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

export default function TodoList({ date, userId, canEdit }: Props) {
  const queryClient = useQueryClient();
  const [managing, setManaging] = useState(false);
  const [addOnOpen, setAddOnOpen] = useState(false);

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
            a.id === todo.id ? { ...a, completed: !a.completed, streak: a.completed ? Math.max(0, a.streak - 1) : a.streak + 1 } : a
          ),
        };
      }
    );
    try {
      await toggleTodo(todo.id, date);
      queryClient.refetchQueries({ queryKey: ['dashboard'] });
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
              {data.todos.map((todo) => (
                <li key={todo.id} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="flex-1 min-w-0">
                    <span className={`text-sm ${todo.completed ? 'text-muted-foreground line-through' : 'text-foreground'}`}>
                      {todo.name}
                    </span>
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
                      className={`flex size-5 shrink-0 items-center justify-center rounded border transition-colors ${
                        todo.completed
                          ? 'border-primary bg-primary text-primary-foreground'
                          : 'border-input bg-muted/50 hover:border-ring'
                      } ${!canEdit ? 'cursor-default' : 'cursor-pointer'}`}
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
              ))}
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
    } catch { /* ignore */ }
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
    } catch { /* ignore */ }
    setSaving(false);
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteTodo(id);
      refresh();
    } catch { /* ignore */ }
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
                    <span className="relative flex items-center">
                      <input value={editTime} onChange={(e) => setEditTime(e.target.value)} type="text" inputMode="numeric" placeholder="HH:MM" pattern="[0-2][0-9]:[0-5][0-9]" maxLength={5} className={`${timeInputClass} pr-8`} />
                      <span className="absolute right-2 text-[10px] text-muted-foreground/60 pointer-events-none">&#128337;</span>
                    </span>
                    {editTime && <button type="button" onClick={() => setEditTime('')} className="rounded-md px-3 py-1.5 text-xs font-semibold text-muted-foreground border border-border bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer">Clear</button>}
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button type="button" onClick={() => setEditingId(null)} className="rounded-md px-4 py-2 text-sm font-semibold text-muted-foreground border border-border bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer">Cancel</button>
                    <button type="button" onClick={() => handleUpdate(todo.id)} disabled={saving} className="rounded-md px-4 py-2 text-sm font-semibold text-primary border border-primary/30 bg-primary/10 hover:bg-primary/20 transition-colors cursor-pointer disabled:opacity-50">Save</button>
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
                    <button type="button" onClick={() => startEdit(todo)} className="rounded-md px-4 py-2 text-sm font-semibold text-primary border border-primary/30 bg-primary/10 hover:bg-primary/20 transition-colors cursor-pointer">Edit</button>
                    <button type="button" onClick={() => handleDelete(todo.id)} className="rounded-md px-4 py-2 text-sm font-semibold text-destructive border border-destructive/30 bg-destructive/10 hover:bg-destructive/20 transition-colors cursor-pointer">Remove</button>
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
              <span className="relative flex items-center">
                <input value={newTime} onChange={(e) => setNewTime(e.target.value)} type="text" inputMode="numeric" placeholder="HH:MM" pattern="[0-2][0-9]:[0-5][0-9]" maxLength={5} className={`${timeInputClass} pr-8`} />
                <span className="absolute right-2 text-[10px] text-muted-foreground/60 pointer-events-none">&#128337;</span>
              </span>
              {newTime && <button type="button" onClick={() => setNewTime('')} className="rounded-md px-3 py-1.5 text-xs font-semibold text-muted-foreground border border-border bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer">Clear</button>}
            </div>
            <div className="flex gap-2 justify-end">
              <button type="button" onClick={() => { setShowAddForm(false); setNewName(''); setNewTime(''); setNewSchedule({ type: 'daily' }); }} className="rounded-md px-4 py-2 text-sm font-semibold text-muted-foreground border border-border bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer">Cancel</button>
              <button type="submit" disabled={!newName.trim() || creating} className="rounded-md px-4 py-2 text-sm font-semibold text-primary border border-primary/30 bg-primary/10 hover:bg-primary/20 transition-colors cursor-pointer disabled:opacity-50">Add</button>
            </div>
          </form>
        ) : (
          <div className="flex items-center justify-between">
            <button type="button" onClick={onClose} className="rounded-md px-4 py-2 text-sm font-semibold text-muted-foreground border border-border bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer">Done</button>
            <button type="button" onClick={() => setShowAddForm(true)} className="rounded-md px-4 py-2 text-sm font-semibold text-primary border border-primary/30 bg-primary/10 hover:bg-primary/20 transition-colors cursor-pointer">Add todo</button>
          </div>
        )}
      </div>
    </div>
  );
}
