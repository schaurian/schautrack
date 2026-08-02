import * as React from 'react';
import { cn } from '@/lib/utils';

// Chevron drawn as a CSS background rather than a sibling SVG element, so this
// component renders exactly ONE node. An earlier version wrapped the select in a
// positioning <span>, which silently broke adjacent-sibling selectors elsewhere
// (`label:text-is("Sex") + select`). A drop-in select replacement must not
// change the shape of the DOM around it.
// Inline data: URI is permitted — the CSP allows `img-src 'self' data: blob:`.
const CHEVRON =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%239aa4b6' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")";

/**
 * A native <select> with the platform arrow replaced by our own.
 *
 * Deliberately still a native select: on a phone this opens the OS picker
 * (wheel on iOS, sheet on Android), which beats any custom listbox we would
 * write, and it keeps keyboard behaviour, screen-reader semantics and
 * Playwright's selectOption() working for free. `color-scheme: dark` on <html>
 * already renders the popup itself dark.
 *
 * For a choice between exactly two values use SegmentedControl instead — a
 * dropdown that hides half its options behind a tap is the wrong control there.
 */
export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, style, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        'w-full appearance-none rounded-[10px] border border-white/10 bg-white/[0.04] py-2 pl-3 pr-9',
        'text-sm text-foreground outline-none transition-colors',
        'hover:border-white/20',
        'focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      style={{
        backgroundImage: CHEVRON,
        backgroundRepeat: 'no-repeat',
        backgroundPosition: 'right 0.75rem center',
        ...style,
      }}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

export default Select;
