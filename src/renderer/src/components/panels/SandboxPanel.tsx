import { Badge } from '../common/Badge';
import { useStore } from '../../store';

export function SandboxPanel() {
  const { vmStatus, vmEvents, vmFindings, vmNetworkSummary } = useStore();
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Sandbox</span>
        <Badge severity={vmStatus === 'running' ? 'clean' : 'low'}>{vmStatus.toUpperCase()}</Badge>
      </div>
      <div className="flex-1 overflow-auto p-2 space-y-3">
        <div className="grid grid-cols-3 gap-2">
          <StatCard label="Events" value={vmEvents.length} />
          <StatCard label="Findings" value={vmFindings.length} />
          <StatCard label="DNS" value={vmNetworkSummary?.dns_query_count ?? 0} />
        </div>
        {vmFindings.length > 0 && (
          <div>
            <div className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] mb-1">Top Findings</div>
            {vmFindings.slice(0, 5).map((f, i) => (
              <div key={i} className="flex items-center gap-2 py-0.5">
                <Badge severity={f.severity}>{f.severity[0].toUpperCase()}</Badge>
                <span className="text-[10px] font-mono text-[var(--st-text-primary)] truncate">{f.title}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[var(--st-bg-elevated)] rounded border border-[var(--st-border)] p-2 text-center">
      <div className="text-[16px] font-bold font-mono text-[var(--st-text-primary)] glow">{value}</div>
      <div className="text-[8px] uppercase tracking-wider text-[var(--st-text-muted)]">{label}</div>
    </div>
  );
}
