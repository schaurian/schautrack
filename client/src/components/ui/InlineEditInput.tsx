import type * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * The <input> that replaces a piece of text while it is being edited in place
 * (an entry name, a share label, a passkey name, ...).
 *
 * It takes its whole typography from the surrounding element via `font: inherit`
 * (size, weight, line-height, family) and `letter-spacing: inherit`, so put the
 * text classes on a wrapper that both the display element and this input sit in,
 * not on either of them. Each call site used to hard-code its own `text-sm` on
 * the input while the display text was e.g. `text-[15px] font-semibold`, so the
 * text visibly shrank and lost its weight the moment you tapped it.
 *
 * Give the display element the same padding and a `border border-transparent`
 * so the box keeps its height when the 1px ring border appears.
 */
export function InlineEditInput({ className, ...props }: React.ComponentProps<'input'>) {
  return (
    <input
      className={cn(
        'min-w-0 rounded-md border border-ring bg-muted/50 text-foreground outline-none [font:inherit] [letter-spacing:inherit]',
        className,
      )}
      {...props}
    />
  );
}
