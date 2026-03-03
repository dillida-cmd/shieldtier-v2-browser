import { useRef, useEffect } from 'react';
import { useStore } from '../../store';
import { cn } from '../../lib/utils';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-[var(--st-severity-critical)]',
  high: 'text-[var(--st-severity-high)]',
  medium: 'text-[var(--st-severity-medium)]',
  low: 'text-[var(--st-severity-low)]',
};

export function VMTerminal() {
  const { vmEvents } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [vmEvents.length]);

  return (
    <div ref={scrollRef} className="flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed bg-[var(--st-bg-primary)]">
      {vmEvents.length === 0 ? (
        <div className="text-[var(--st-text-muted)] text-[10px]">
          <span className="text-[var(--st-severity-clean)]">root@sandbox:~#</span> Waiting for VM events...
        </div>
      ) : (
        vmEvents.map((event, i) => (
          <div key={i} className="flex gap-2 hover:bg-[var(--st-bg-hover)] px-1 rounded">
            <span className="text-[var(--st-text-muted)] flex-shrink-0 text-[10px]">
              {event.timestamp}
            </span>
            <span className="text-[var(--st-severity-clean)] flex-shrink-0">
              [agent]
            </span>
            <span className={cn(
              event.severity ? SEVERITY_COLORS[event.severity] : 'text-[var(--st-text-primary)]',
            )}>
              {event.detail}
            </span>
          </div>
        ))
      )}
    </div>
  );
}
