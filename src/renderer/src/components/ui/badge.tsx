import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md font-medium transition-colors',
  {
    variants: {
      variant: {
        default:
          'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]',
        success: 'bg-[color:var(--st-success-dim)] text-[color:var(--st-success)]',
        warning: 'bg-[color:var(--st-warning-dim)] text-[color:var(--st-warning)]',
        destructive: 'bg-[color:var(--st-danger-dim)] text-[color:var(--st-danger)]',
        purple: 'bg-[color:var(--st-purple-dim)] text-[color:var(--st-purple)]',
        outline:
          'border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)]',
      },
      size: {
        sm: 'text-[9px] px-1.5 py-px',
        default: 'text-[10px] px-2 py-0.5',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
);

interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, size, ...props }, ref) => (
    <span
      ref={ref}
      className={cn(badgeVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Badge.displayName = 'Badge';

export { Badge, badgeVariants };
export type { BadgeProps };
