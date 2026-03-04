import { useMemo, useState } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import type { Finding, SeverityLevel } from '../../ipc/types';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const ENGINE_COLORS: Record<string, string> = {
  yara: 'bg-purple-500/15 text-purple-400',
  file_analysis: 'bg-blue-500/15 text-blue-400',
  vm_sandbox: 'bg-amber-500/15 text-amber-400',
};

const FILTERS = ['ALL', 'CRIT', 'HIGH', 'MED', 'LOW'] as const;
type SevFilter = (typeof FILTERS)[number];

const FILTER_MAP: Record<SevFilter, SeverityLevel | null> = {
  ALL: null,
  CRIT: 'critical',
  HIGH: 'high',
  MED: 'medium',
  LOW: 'low',
};

export function FindingsPanel() {
  const { analysisResult, vmFindings } = useStore();
  const [filter, setFilter] = useState<SevFilter>('ALL');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const findings = useMemo(() => {
    const all: Finding[] = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return all.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  }, [analysisResult, vmFindings]);

  const filtered = useMemo(() => {
    const sev = FILTER_MAP[filter];
    if (!sev) return findings;
    return findings.filter((f) => f.severity === sev);
  }, [findings, filter]);

  const toggle = (idx: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx); else next.add(idx);
      return next;
    });
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Findings</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{filtered.length}</span>
        <div className="flex-1" />
        <div className="flex gap-0.5">
          {FILTERS.map((f) => (
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
      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <EmptyState message="No findings yet" submessage="Findings appear when analysis engines detect threats" />
        ) : (
          filtered.map((f, i) => (
            <div
              key={i}
              className="border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors cursor-pointer"
              onClick={() => toggle(i)}
            >
              <div className="flex items-center gap-2 px-2 py-1.5">
                <span className={cn('text-[10px] transition-transform', expanded.has(i) ? 'rotate-90' : '')}>▶</span>
                <Badge severity={f.severity}>{f.severity}</Badge>
                <span className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold truncate">{f.title}</span>
                <span className={cn('text-[10px] font-bold px-1 rounded ml-auto flex-shrink-0', ENGINE_COLORS[f.engine] ?? 'bg-[var(--st-bg-elevated)] text-[var(--st-text-label)]')}>
                  {f.engine}
                </span>
              </div>
              {expanded.has(i) && (
                <div className="px-2 pb-2 pl-7 collapse-enter">
                  <div className="text-[10px] text-[var(--st-text-label)] mb-1.5">{f.description}</div>
                  {Object.keys(f.metadata).length > 0 && (
                    <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px]">
                      {Object.entries(f.metadata).map(([k, v]) => (
                        <div key={k} className="flex gap-1">
                          <span className="text-[var(--st-text-muted)]">{k}:</span>
                          <span className="text-[var(--st-text-label)] font-mono truncate">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
