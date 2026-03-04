import { cn } from '../../lib/utils';

interface EmptyStateProps {
  icon?: React.ReactNode;
  message: string;
  submessage?: string;
  className?: string;
}

export function EmptyState({ icon, message, submessage, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center h-full gap-2 text-center px-4', className)}>
      {icon && <div className="text-[var(--st-text-muted)] opacity-30">{icon}</div>}
      <span className="text-[11px] text-[var(--st-text-muted)]">{message}</span>
      {submessage && <span className="text-[10px] text-[var(--st-text-muted)] opacity-60">{submessage}</span>}
    </div>
  );
}

interface SkeletonRowProps {
  count?: number;
  className?: string;
}

export function SkeletonRow({ count = 3, className }: SkeletonRowProps) {
  return (
    <div className={cn('space-y-1 p-2', className)}>
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className="h-5 rounded shimmer bg-[var(--st-bg-elevated)]"
          style={{ width: `${70 + Math.random() * 30}%` }}
        />
      ))}
    </div>
  );
}
