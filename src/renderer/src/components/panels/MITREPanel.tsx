import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface MitreTechnique { id: string; title: string; severity: SeverityLevel; count: number; source: string; }

const ENGINE_GROUPS: Record<string, string> = {
  yara: 'YARA Detections',
  file_analysis: 'Static Analysis',
  vm_sandbox: 'VM Behavior',
};

function extractGroupedTechniques(findings: Finding[]): Map<string, MitreTechnique[]> {
  const groups = new Map<string, Map<string, MitreTechnique>>();

  for (const f of findings) {
    const id = String(f.metadata.mitre ?? '');
    if (!id) continue;
    const group = ENGINE_GROUPS[f.engine] ?? 'Network';
    if (!groups.has(group)) groups.set(group, new Map());
    const map = groups.get(group)!;
    const existing = map.get(id);
    if (existing) {
      existing.count++;
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      if (order.indexOf(f.severity) < order.indexOf(existing.severity)) existing.severity = f.severity;
    } else {
      map.set(id, { id, title: f.title, severity: f.severity, count: 1, source: f.engine });
    }
  }

  const result = new Map<string, MitreTechnique[]>();
  for (const [group, map] of groups) {
    const techs = Array.from(map.values()).sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    });
    result.set(group, techs);
  }
  return result;
}

export function MITREPanel() {
  const { analysisResult, vmFindings } = useStore();
  const grouped = useMemo(() => {
    return extractGroupedTechniques([...(analysisResult?.verdict?.findings ?? []), ...vmFindings]);
  }, [analysisResult, vmFindings]);

  const totalCount = useMemo(() => {
    let count = 0;
    for (const techs of grouped.values()) count += techs.length;
    return count;
  }, [grouped]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">MITRE ATT&CK</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{totalCount}</span>
      </div>
      <div className="flex-1 overflow-auto p-2">
        {totalCount === 0 ? (
          <EmptyState message="No techniques mapped" submessage="MITRE ATT&CK techniques appear from analysis findings" />
        ) : (
          <div className="flex gap-3 overflow-x-auto min-h-0">
            {Array.from(grouped).map(([group, techs]) => (
              <div key={group} className="flex-shrink-0 min-w-40">
                <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] mb-1.5">{group}</div>
                <div className="space-y-1">
                  {techs.map((t) => (
                    <div key={t.id} className="flex items-center gap-1.5 px-2 py-1 rounded border border-[var(--st-border)] bg-[var(--st-bg-elevated)] hover:bg-[var(--st-bg-hover)] transition-colors cursor-default" title={`${t.id}: ${t.title}`}>
                      <Badge severity={t.severity}>{t.id}</Badge>
                      <span className="text-[10px] text-[var(--st-text-label)] truncate">{t.title}</span>
                      {t.count > 1 && <span className="text-[10px] text-[var(--st-text-muted)] ml-auto">×{t.count}</span>}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
