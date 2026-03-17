import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[color:var(--st-accent)] disabled:pointer-events-none disabled:opacity-40 [&_svg]:pointer-events-none [&_svg]:shrink-0 cursor-pointer',
  {
    variants: {
      variant: {
        default:
          'bg-[color:var(--st-accent)] text-white hover:brightness-110',
        destructive:
          'bg-[color:var(--st-danger)] text-white hover:brightness-110',
        ghost:
          'bg-transparent hover:bg-[color:var(--st-border-subtle)] text-[color:var(--st-text-secondary)]',
        outline:
          'border border-[color:var(--st-border)] bg-transparent text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]',
        link:
          'text-[color:var(--st-accent)] underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-7 px-2.5 text-[11px]',
        default: 'h-8 px-3 text-[12px]',
        lg: 'h-9 px-4 text-[13px]',
        icon: 'h-7 w-7',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
);

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
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

export { Button, buttonVariants };
export type { ButtonProps };
