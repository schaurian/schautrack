import * as React from 'react';
import { cn } from '@/lib/utils';

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  type?: 'success' | 'error' | 'warning';
  message?: string;
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ className, type = 'error', message, children, ...props }, ref) => (
    <div
      ref={ref}
      role="alert"
      className={cn(
        'relative w-full rounded-md border px-4 py-3 text-sm',
        {
          'border-success/30 bg-success/10 text-green-400': type === 'success',
          'border-destructive/30 bg-destructive/10 text-red-400': type === 'error',
          'border-warning/30 bg-warning/10 text-yellow-400': type === 'warning',
        },
        className
      )}
      {...props}
    >
      {message || children}
    </div>
  )
);
Alert.displayName = 'Alert';

export { Alert };
export default Alert;
