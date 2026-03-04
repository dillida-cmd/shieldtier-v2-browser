import { useMemo, useState, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { EmptyState, SkeletonRow } from '../ui/EmptyState';
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
const TYPE_FILTERS = ['ALL', 'DNS', 'IP', 'URL', 'HASH'] as const;
type TypeFilter = (typeof TYPE_FILTERS)[number];

const SEVERITY_TEXT: Record<string, string> = {
  critical: 'text-[var(--st-severity-critical)]',
  high: 'text-[var(--st-severity-high)]',
  medium: 'text-[var(--st-severity-medium)]',
  low: 'text-[var(--st-severity-low)]',
  info: 'text-[var(--st-text-primary)]',
};

const TYPE_TO_FILTER: Record<string, TypeFilter> = {
  domain: 'DNS',
  ip: 'IP',
  url: 'URL',
  hash: 'HASH',
};

export function IOCPanel() {
  const { analysisResult, vmFindings, analysisStatus } = useStore();
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('ALL');
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const iocs = useMemo(() => {
    const allFindings = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return extractIOCs(allFindings);
  }, [analysisResult, vmFindings]);

  const filtered = useMemo(() => {
    if (typeFilter === 'ALL') return iocs;
    return iocs.filter((ioc) => TYPE_TO_FILTER[ioc.type] === typeFilter);
  }, [iocs, typeFilter]);

  const copyValue = useCallback((value: string, idx: number) => {
    navigator.clipboard.writeText(value);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  }, []);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">IOC</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{filtered.length}</span>
        <div className="flex-1" />
        <div className="flex gap-0.5">
          {TYPE_FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setTypeFilter(f)}
              className={cn(
                'text-[10px] font-bold px-1.5 py-0.5 rounded border-none cursor-pointer transition-colors',
                typeFilter === f
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
        {analysisStatus === 'pending' && iocs.length === 0 ? (
          <SkeletonRow count={4} />
        ) : filtered.length === 0 ? (
          <EmptyState message="No indicators extracted" submessage="IOCs will appear when analysis detects network indicators" />
        ) : (
          filtered.map((ioc, i) => (
            <div
              key={i}
              className="group flex items-center gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors"
            >
              <Badge severity={ioc.severity === 'critical' || ioc.severity === 'high' ? 'high' : 'info'} className="flex-shrink-0 w-9 justify-center">
                {TYPE_ICONS[ioc.type]}
              </Badge>
              <span className={cn('text-[11px] font-mono truncate flex-1', SEVERITY_TEXT[ioc.severity] ?? 'text-[var(--st-text-primary)]')}>
                {ioc.value}
              </span>
              <button
                onClick={() => copyValue(ioc.value, i)}
                className="opacity-0 group-hover:opacity-100 text-[var(--st-text-muted)] hover:text-[var(--st-text-primary)] bg-transparent border-none cursor-pointer transition-opacity text-[10px]"
              >
                {copiedIdx === i ? '✓' : '⧉'}
              </button>
              <span className="text-[10px] font-bold px-1 rounded bg-blue-500/15 text-blue-400">{ioc.source}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
