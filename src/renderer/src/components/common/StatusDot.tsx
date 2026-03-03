import { cn } from '../../lib/utils';

interface StatusDotProps {
  status: 'idle' | 'active' | 'error' | 'recording';
  className?: string;
}

const STATUS_STYLES = {
  idle: 'bg-[var(--st-text-muted)]',
  active: 'bg-[var(--st-severity-clean)]',
  error: 'bg-[var(--st-severity-critical)]',
  recording: 'bg-[var(--st-severity-critical)]',
};

export function StatusDot({ status, className }: StatusDotProps) {
  return (
    <span className={cn('relative inline-flex h-2 w-2', className)}>
      {(status === 'active' || status === 'recording') && (
        <span className={cn(
          'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
          STATUS_STYLES[status],
        )} />
      )}
      <span className={cn('relative inline-flex rounded-full h-2 w-2', STATUS_STYLES[status])} />
    </span>
  );
}
