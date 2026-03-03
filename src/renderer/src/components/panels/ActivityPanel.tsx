import { useRef, useEffect, useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface ActivityEvent { timestamp: string; icon: string; label: string; detail: string; severity: SeverityLevel; }

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
  const { analysisResult, vmFindings } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  const events = useMemo(() => {
    return findingsToActivity([...(analysisResult?.verdict?.findings ?? []), ...vmFindings]);
  }, [analysisResult, vmFindings]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [events.length]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Activity</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{events.length}</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-auto">
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No activity yet</div>
        ) : (
          events.map((e, i) => (
            <div key={i} className="flex items-start gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <span className="text-[9px] font-mono text-[var(--st-text-muted)] flex-shrink-0 pt-0.5">{e.timestamp}</span>
              <Badge severity={e.severity} className="flex-shrink-0 mt-0.5">{e.icon}</Badge>
              <div className="min-w-0">
                <div className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold truncate">{e.label}</div>
                <div className="text-[9px] text-[var(--st-text-label)] truncate">{e.detail}</div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
