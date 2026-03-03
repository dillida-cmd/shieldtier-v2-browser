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

interface BadgeProps {
  severity: Severity;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ severity, children, className }: BadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono',
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
    <span className={cn(
      'text-[9px] font-bold font-mono px-1 rounded',
      COUNT_COLORS[color],
      className,
    )}>
      {count > 99 ? '99+' : count}
    </span>
  );
}
