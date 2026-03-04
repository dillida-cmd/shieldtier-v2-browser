import { useRef, useEffect } from 'react';
import { cn } from '../../lib/utils';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-[var(--st-severity-critical)]',
  high: 'bg-[var(--st-severity-high)]',
  medium: 'bg-[var(--st-severity-medium)]',
  low: 'bg-[var(--st-severity-low)]',
};

export function TimelinePanel() {
  const { vmEvents } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [vmEvents.length]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Timeline</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{vmEvents.length}</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-auto">
        {vmEvents.length === 0 ? (
          <EmptyState message="No timeline events" submessage="VM events will appear chronologically here" />
        ) : (
          <div className="py-1">
            {vmEvents.map((event, i) => (
              <div key={i} className="flex items-start gap-2 px-2 py-1 hover:bg-[var(--st-bg-hover)] transition-colors">
                <span className="text-[10px] font-mono text-[var(--st-text-muted)] flex-shrink-0 w-16 pt-0.5">{event.timestamp}</span>
                <div className="flex flex-col items-center flex-shrink-0 pt-1">
                  <div className={cn('w-2 h-2 rounded-full', event.severity ? SEVERITY_DOT[event.severity] : 'bg-[var(--st-text-muted)]')} />
                  {i < vmEvents.length - 1 && <div className="w-px flex-1 bg-[var(--st-border)] min-h-3 mt-0.5" />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] font-bold text-[var(--st-accent)] uppercase">[{event.category}]</span>
                    <span className="text-[11px] font-mono text-[var(--st-text-primary)] truncate">{event.action}</span>
                  </div>
                  <div className="text-[10px] text-[var(--st-text-label)] truncate">{event.detail}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
