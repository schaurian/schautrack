import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cn } from '@/lib/utils';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'ghost' | 'destructive' | 'outline';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  asChild?: boolean;
  loading?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', asChild = false, loading, children, disabled, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(
          'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[10px] font-bold text-sm cursor-pointer',
          'transition-[filter,transform] duration-100 ease-out',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0ea5e9] focus-visible:ring-offset-2 focus-visible:ring-offset-background',
          'disabled:pointer-events-none disabled:opacity-40 disabled:saturate-0',
          {
            // Primary: cyan bordered — use for the main/confirm action
            'border border-[#0ea5e9]/60 text-[#0ea5e9] bg-[#0ea5e9]/[0.07] hover:bg-[#0ea5e9]/[0.13] hover:border-[#0ea5e9]/90 active:translate-y-px': variant === 'default',
            // Ghost: no border, muted — use for cancel/dismiss actions only
            'bg-transparent text-foreground/70 hover:bg-white/[0.06] hover:text-foreground active:translate-y-px': variant === 'ghost',
            // Destructive: red bordered — use for irreversible/dangerous actions
            'border border-destructive/60 text-destructive bg-destructive/[0.07] hover:bg-destructive/[0.13] hover:border-destructive/90 active:translate-y-px': variant === 'destructive',
            // Outline: purple bordered — use for secondary actions
            'border border-[#a855f7]/60 text-[#a855f7] bg-[#a855f7]/[0.07] hover:bg-[#a855f7]/[0.13] hover:border-[#a855f7]/90 active:translate-y-px': variant === 'outline',
          },
          {
            'h-9 px-4': size === 'default',
            'h-8 px-3 text-xs': size === 'sm',
            'h-11 px-6': size === 'lg',
            'h-9 w-9 p-0': size === 'icon',
          },
          className
        )}
        ref={ref}
        disabled={disabled || loading}
        {...props}
      >
        {loading ? (
          <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        ) : children}
      </Comp>
    );
  }
);
Button.displayName = 'Button';

export { Button };
export default Button;
