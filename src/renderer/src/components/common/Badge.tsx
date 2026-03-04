import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'clean';

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)]',
  high: 'bg-[var(--st-severity-high)]/15 text-[var(--st-severity-high)]',
  medium: 'bg-[var(--st-severity-medium)]/15 text-[var(--st-severity-medium)]',
  low: 'bg-[var(--st-severity-low)]/15 text-[var(--st-severity-low)]',
  info: 'bg-[var(--st-accent)]/15 text-[var(--st-accent)]',
  clean: 'bg-[var(--st-severity-clean)]/15 text-[var(--st-severity-clean)]',
};

const badgeVariants = cva(
  'inline-flex items-center font-bold uppercase tracking-wider font-mono',
  {
    variants: {
      variant: {
        severity: 'px-1.5 py-0.5 rounded text-[10px]',
        count: 'px-1 rounded text-[10px]',
        pill: 'px-2 py-0.5 rounded-full text-[10px]',
        outline: 'px-1.5 py-0.5 rounded text-[10px] border border-[var(--st-border)]',
      },
    },
    defaultVariants: {
      variant: 'severity',
    },
  },
);

interface BadgeProps extends VariantProps<typeof badgeVariants> {
  severity: Severity;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ severity, children, className, variant }: BadgeProps) {
  return (
    <span className={cn(
      badgeVariants({ variant }),
      SEVERITY_STYLES[severity],
      className,
    )}>
      {children}
    </span>
  );
}

interface CountBadgeProps {
  count: number;
  color?: 'blue' | 'red' | 'purple' | 'green';
  className?: string;
}

const COUNT_COLORS = {
  blue: 'bg-blue-500/15 text-blue-400',
  red: 'bg-red-500/15 text-red-400',
  purple: 'bg-purple-500/15 text-purple-400',
  green: 'bg-green-500/15 text-green-400',
};

export function CountBadge({ count, color = 'blue', className }: CountBadgeProps) {
  if (count <= 0) return null;
  return (
    <span
      key={count}
      className={cn(
        'text-[10px] font-bold font-mono px-1 rounded animate-badge-pop',
        COUNT_COLORS[color],
        className,
      )}
    >
      {count > 99 ? '99+' : count}
    </span>
  );
}
