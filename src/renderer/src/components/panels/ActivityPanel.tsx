import { useRef, useEffect, useMemo, useState } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface ActivityEvent { timestamp: string; icon: string; label: string; detail: string; severity: SeverityLevel; }

const EVENT_FILTERS = ['ALL', 'YARA', 'FILE', 'VM', 'IOC'] as const;
type EventFilter = (typeof EVENT_FILTERS)[number];

function findingsToActivity(findings: Finding[]): ActivityEvent[] {
  const now = new Date();
  return findings.map((f, i) => {
    const ts = new Date(now.getTime() - (findings.length - i) * 1000);
    const timeStr = ts.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const icon = f.engine === 'yara' ? 'YARA' : f.engine === 'file_analysis' ? 'FILE' : f.engine === 'vm_sandbox' ? 'VM' : 'IOC';
    return { timestamp: timeStr, icon, label: f.title, detail: f.description, severity: f.severity };
  });
}

export function ActivityPanel() {
  const { analysisResult, vmFindings, analysisStatus } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [filter, setFilter] = useState<EventFilter>('ALL');

  const events = useMemo(() => {
    return findingsToActivity([...(analysisResult?.verdict?.findings ?? []), ...vmFindings]);
  }, [analysisResult, vmFindings]);

  const filtered = useMemo(() => {
    if (filter === 'ALL') return events;
    return events.filter((e) => e.icon === filter);
  }, [events, filter]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [filtered.length]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Activity</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{filtered.length}</span>
        <div className="flex-1" />
        <div className="flex gap-0.5">
          {EVENT_FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'text-[10px] font-bold px-1.5 py-0.5 rounded border-none cursor-pointer transition-colors',
                filter === f
                  ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)]'
                  : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-label)]',
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-auto">
        {analysisStatus === 'pending' && events.length === 0 ? (
          <div className="px-2 py-1 font-mono text-[11px]">
            <span className="text-[var(--st-severity-clean)]">root@sandbox:~#</span>
            <span className="text-[var(--st-text-label)] ml-1">Running analysis...</span>
            <span className="inline-block w-2 h-3 bg-[var(--st-text-primary)] ml-0.5 terminal-cursor" />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState message="No activity yet" submessage="Events appear as analysis engines run" />
        ) : (
          filtered.map((e, i) => (
            <div
              key={i}
              className="flex items-start gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors stagger-in"
              style={{ '--item-index': i } as React.CSSProperties}
            >
              <span className="text-[10px] font-mono text-[var(--st-text-muted)] flex-shrink-0 pt-0.5">{e.timestamp}</span>
              <Badge severity={e.severity} className="flex-shrink-0 mt-0.5">{e.icon}</Badge>
              <div className="min-w-0">
                <div className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold truncate">{e.label}</div>
                <div className="text-[10px] text-[var(--st-text-label)] truncate">{e.detail}</div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
