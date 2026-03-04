import { useRef, useEffect } from 'react';
import { useStore } from '../../store';
import { cn } from '../../lib/utils';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-[var(--st-severity-critical)]',
  high: 'text-[var(--st-severity-high)]',
  medium: 'text-[var(--st-severity-medium)]',
  low: 'text-[var(--st-severity-low)]',
};

const CATEGORY_COLORS: Record<string, string> = {
  PROC: 'text-[var(--st-severity-clean)]',
  NET: 'text-[var(--st-severity-low)]',
  FILE: 'text-[var(--st-severity-medium)]',
  REG: 'text-purple-400',
};

export function VMTerminal() {
  const { vmEvents, vmStatus } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [vmEvents.length]);

  return (
    <div ref={scrollRef} className="flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed glass-terminal">
      {vmEvents.length === 0 ? (
        <div className="text-[var(--st-text-muted)] text-[10px]">
          <span className="text-[var(--st-severity-clean)]">root@sandbox:~#</span> Waiting for VM events...
          {vmStatus === 'running' && <span className="inline-block w-2 h-3 bg-[var(--st-text-primary)] ml-0.5 terminal-cursor" />}
        </div>
      ) : (
        <>
          {vmEvents.map((event, i) => {
            const cat = event.category.toUpperCase();
            return (
              <div key={i} className="flex gap-2 hover:bg-[var(--st-bg-hover)] px-1 rounded">
                <span className="text-[var(--st-text-muted)] flex-shrink-0 text-[10px]">
                  {event.timestamp}
                </span>
                <span className={cn('flex-shrink-0', CATEGORY_COLORS[cat] ?? 'text-[var(--st-severity-clean)]')}>
                  [{cat}]
                </span>
                <span className={cn(
                  event.severity ? SEVERITY_COLORS[event.severity] : 'text-[var(--st-text-primary)]',
                )}>
                  {event.detail}
                </span>
              </div>
            );
          })}
          {vmStatus === 'running' && (
            <div className="text-[var(--st-text-muted)] text-[10px] mt-1">
              <span className="text-[var(--st-severity-clean)]">root@sandbox:~#</span>
              <span className="inline-block w-2 h-3 bg-[var(--st-text-primary)] ml-0.5 terminal-cursor" />
            </div>
          )}
        </>
      )}
    </div>
  );
}
