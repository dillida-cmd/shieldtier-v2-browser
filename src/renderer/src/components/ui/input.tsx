import * as React from 'react';
import { cn } from '../../lib/utils';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          'h-8 w-full rounded-md border border-[color:var(--st-border)] bg-[color:var(--st-bg-base)] px-2.5 py-1 text-[12px] text-[color:var(--st-text-primary)] placeholder:text-[color:var(--st-text-muted)] transition-colors focus:border-[color:var(--st-accent)] focus:outline-none disabled:cursor-not-allowed disabled:opacity-40',
          className,
        )}
        ref={ref}
        {...props}
      />
    );
  },
);
Input.displayName = 'Input';

export { Input };
export type { InputProps };
