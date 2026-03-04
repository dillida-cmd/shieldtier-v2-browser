import { useCallback } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import { ipcCall } from '../../ipc/bridge';

export function SandboxPanel() {
  const { vmStatus, vmEvents, vmFindings, vmNetworkSummary, currentSha256 } = useStore();

  const submitToVm = useCallback(async () => {
    if (!currentSha256) return;
    try {
      await ipcCall('submit_sample_to_vm', { sha256: currentSha256 });
    } catch (e) {
      console.error('Failed to submit to VM:', e);
    }
  }, [currentSha256]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Sandbox</span>
        <Badge severity={vmStatus === 'running' ? 'clean' : vmStatus === 'error' ? 'critical' : 'low'}>{vmStatus.toUpperCase()}</Badge>
        <div className="flex-1" />
        {currentSha256 && vmStatus === 'idle' && (
          <button
            onClick={submitToVm}
            className="text-[10px] font-bold px-2 py-0.5 rounded border-none cursor-pointer bg-[var(--st-accent-dim)] text-[var(--st-accent)] hover:bg-[var(--st-accent)]/20 transition-colors"
          >
            Submit to VM
          </button>
        )}
      </div>
      <div className="flex-1 overflow-auto p-2 space-y-3">
        {vmStatus === 'idle' && vmEvents.length === 0 ? (
          <EmptyState
            message={`VM Sandbox — ${vmStatus.toUpperCase()}`}
            submessage="Start a VM or submit a sample to analyze behavior"
          />
        ) : (
          <>
            <div className="grid grid-cols-5 gap-2">
              <StatCard label="Events" value={vmEvents.length} />
              <StatCard label="Findings" value={vmFindings.length} />
              <StatCard label="DNS" value={vmNetworkSummary?.dns_query_count ?? 0} />
              <StatCard label="HTTP" value={vmNetworkSummary?.http_request_count ?? 0} />
              <StatCard label="Conns" value={vmNetworkSummary?.connection_count ?? 0} />
            </div>
            {vmFindings.length > 0 && (
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] mb-1">Top Findings</div>
                {vmFindings.slice(0, 5).map((f, i) => (
                  <div key={i} className="flex items-center gap-2 py-0.5">
                    <Badge severity={f.severity}>{f.severity[0].toUpperCase()}</Badge>
                    <span className="text-[10px] font-mono text-[var(--st-text-primary)] truncate">{f.title}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[var(--st-bg-elevated)] rounded border border-[var(--st-border)] p-2 text-center">
      <div className="text-[16px] font-bold font-mono text-[var(--st-text-primary)] glow">{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)]">{label}</div>
    </div>
  );
}
