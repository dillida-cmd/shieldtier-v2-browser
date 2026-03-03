import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { SeverityLevel } from '../../ipc/types';

interface IOCEntry {
  value: string;
  type: 'domain' | 'ip' | 'hash' | 'url';
  source: string;
  severity: SeverityLevel;
}

function extractIOCs(findings: Array<{ metadata: Record<string, unknown>; severity: SeverityLevel }>): IOCEntry[] {
  const seen = new Set<string>();
  const iocs: IOCEntry[] = [];

  for (const f of findings) {
    const meta = f.metadata;
    const entries: Array<{ value: string; type: IOCEntry['type'] }> = [];

    if (typeof meta.domain === 'string') entries.push({ value: meta.domain, type: 'domain' });
    if (typeof meta.destination === 'string') entries.push({ value: meta.destination, type: 'ip' });
    if (typeof meta.path === 'string' && (meta.path as string).match(/^https?:\/\//)) entries.push({ value: meta.path as string, type: 'url' });

    for (const e of entries) {
      if (seen.has(e.value)) continue;
      seen.add(e.value);
      iocs.push({ value: e.value, type: e.type, source: String(meta.mitre ?? 'analysis'), severity: f.severity });
    }
  }
  return iocs;
}

const TYPE_ICONS: Record<string, string> = { domain: 'DNS', ip: 'IP', hash: 'HASH', url: 'URL' };

export function IOCPanel() {
  const { analysisResult, vmFindings } = useStore();

  const iocs = useMemo(() => {
    const allFindings = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return extractIOCs(allFindings);
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">IOC</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{iocs.length}</span>
      </div>
      <div className="flex-1 overflow-auto">
        {iocs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No indicators extracted</div>
        ) : (
          iocs.map((ioc, i) => (
            <div key={i} className="flex items-center gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <Badge severity={ioc.severity === 'critical' || ioc.severity === 'high' ? 'high' : 'info'} className="flex-shrink-0 w-9 justify-center">
                {TYPE_ICONS[ioc.type]}
              </Badge>
              <span className="text-[11px] font-mono text-[var(--st-text-primary)] truncate flex-1">{ioc.value}</span>
              <span className="text-[8px] font-bold px-1 rounded bg-blue-500/15 text-blue-400">{ioc.source}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
