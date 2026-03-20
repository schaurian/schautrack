import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getTodosDay, toggleTodo } from '@/api/todos';
import type { TodoDay } from '@/types';

interface Props {
  date: string;
  userId: number;
  canEdit: boolean;
}

export default function TodoList({ date, userId, canEdit }: Props) {
  const queryClient = useQueryClient();

  const { data } = useQuery({
    queryKey: ['todos-day', userId, date],
    queryFn: () => getTodosDay(date, userId),
    enabled: !!date && !!userId,
  });

  if (!data?.enabled || !data.todos?.length) return null;

  const handleToggle = async (todo: TodoDay) => {
    if (!canEdit) return;

    // Optimistic update
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
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['todos-day', userId, date] });
    } catch {
      // Revert on error
      queryClient.invalidateQueries({ queryKey: ['todos-day', userId, date] });
    }
  };

  const completed = data.todos.filter((a) => a.completed).length;
  const total = data.todos.length;

  return (
    <div className="rounded-xl border-2 border-border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b-2 border-border flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Todos</h3>
        <span className="text-xs text-muted-foreground">{completed}/{total}</span>
      </div>
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
    </div>
  );
}
