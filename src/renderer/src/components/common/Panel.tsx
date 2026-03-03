import { cn } from '../../lib/utils';

interface PanelProps {
  title?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPad?: boolean;
}

export function Panel({ title, actions, children, className, noPad }: PanelProps) {
  return (
    <div className={cn('flex flex-col h-full bg-[var(--st-bg-panel)] border border-[var(--st-border)] rounded-sm overflow-hidden', className)}>
      {title && (
        <div className="flex items-center justify-between h-7 px-2 border-b border-[var(--st-border)] flex-shrink-0">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">{title}</span>
          {actions && <div className="flex items-center gap-1">{actions}</div>}
        </div>
      )}
      <div className={cn('flex-1 overflow-auto', !noPad && 'p-2')}>
        {children}
      </div>
    </div>
  );
}
