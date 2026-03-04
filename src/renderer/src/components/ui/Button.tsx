import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded font-mono font-bold uppercase tracking-wider transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--st-accent)] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer border-none',
  {
    variants: {
      variant: {
        ghost: 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)]',
        primary: 'bg-[var(--st-accent-dim)] text-[var(--st-accent)] hover:bg-[var(--st-accent)]/20',
        danger: 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)] hover:bg-[var(--st-severity-critical)]/25',
        terminal: 'bg-transparent text-[var(--st-text-primary)] hover:bg-[var(--st-accent-dim)] glow',
      },
      size: {
        xs: 'h-5 px-1.5 text-[10px]',
        sm: 'h-6 px-2 text-[10px]',
        default: 'h-7 px-3 text-[11px]',
      },
    },
    defaultVariants: {
      variant: 'ghost',
      size: 'default',
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = 'Button';
