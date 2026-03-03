import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface MitreTechnique { id: string; title: string; severity: SeverityLevel; count: number; }

function extractMitreTechniques(findings: Finding[]): MitreTechnique[] {
  const map = new Map<string, MitreTechnique>();
  for (const f of findings) {
    const id = String(f.metadata.mitre ?? '');
    if (!id) continue;
    const existing = map.get(id);
    if (existing) {
      existing.count++;
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      if (order.indexOf(f.severity) < order.indexOf(existing.severity)) existing.severity = f.severity;
    } else {
      map.set(id, { id, title: f.title, severity: f.severity, count: 1 });
    }
  }
  return Array.from(map.values()).sort((a, b) => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return order.indexOf(a.severity) - order.indexOf(b.severity);
  });
}

export function MITREPanel() {
  const { analysisResult, vmFindings } = useStore();
  const techniques = useMemo(() => {
    return extractMitreTechniques([...(analysisResult?.verdict?.findings ?? []), ...vmFindings]);
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">MITRE ATT&CK</span>
      </div>
      <div className="flex-1 overflow-auto p-2">
        {techniques.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No techniques mapped</div>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {techniques.map((t) => (
              <div key={t.id} className="flex items-center gap-1.5 px-2 py-1 rounded border border-[var(--st-border)] bg-[var(--st-bg-elevated)] hover:bg-[var(--st-bg-hover)] transition-colors cursor-default" title={`${t.id}: ${t.title}`}>
                <Badge severity={t.severity}>{t.id}</Badge>
                <span className="text-[10px] text-[var(--st-text-label)] max-w-32 truncate">{t.title}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
