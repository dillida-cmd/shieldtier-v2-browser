import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding } from '../../ipc/types';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function FindingsPanel() {
  const { analysisResult, vmFindings } = useStore();

  const findings = useMemo(() => {
    const all: Finding[] = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return all.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Findings</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{findings.length}</span>
      </div>
      <div className="flex-1 overflow-auto">
        {findings.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No findings yet</div>
        ) : (
          findings.map((f, i) => (
            <div key={i} className="px-2 py-1.5 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <div className="flex items-center gap-2">
                <Badge severity={f.severity}>{f.severity}</Badge>
                <span className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold">{f.title}</span>
                <span className="text-[9px] text-[var(--st-text-muted)] ml-auto flex-shrink-0">{f.engine}</span>
              </div>
              <div className="text-[10px] text-[var(--st-text-label)] mt-0.5 pl-0.5">{f.description}</div>
              {f.metadata.mitre && (
                <span className="inline-block mt-0.5 text-[8px] font-bold font-mono bg-[var(--st-accent)]/15 text-[var(--st-accent)] px-1 rounded">
                  {String(f.metadata.mitre)}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
