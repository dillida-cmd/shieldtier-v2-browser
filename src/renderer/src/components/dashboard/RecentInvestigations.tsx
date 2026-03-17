import React, { useEffect, useState } from 'react';

interface CaseRecord {
  id: string;
  caseId: string;
  caseName: string;
  createdAt: string;
  status?: string;
}

export function RecentInvestigations() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const result = await window.shieldtier.auth.getCases();
        if (result.success && result.cases) {
          setCases(result.cases.slice(0, 8));
        }
      } catch {
        // Silently fail — dashboard is informational
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div>
      <h3 className="text-xs font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-3">
        Recent Investigations
      </h3>
      <div className="glass rounded-xl border">
        {loading ? (
          <div className="p-4 space-y-2" aria-label="Loading" role="status">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-10 rounded-lg bg-[color:var(--st-border-subtle)] shimmer" />
            ))}
          </div>
        ) : cases.length === 0 ? (
          <div className="p-8 text-center">
            <div className="w-10 h-10 rounded-lg bg-[color:var(--st-accent-dim)] flex items-center justify-center mx-auto mb-3">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[color:var(--st-text-muted)]">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
              </svg>
            </div>
            <p className="text-sm text-[color:var(--st-text-muted)]">No previous investigations</p>
            <p className="text-xs text-[color:var(--st-text-muted)] mt-1 opacity-50">
              Use <kbd className="font-mono bg-[color:var(--st-accent-dim)] rounded px-1 py-0.5 border border-[color:var(--st-border-subtle)]">New Investigation</kbd> above to start your first case
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[color:var(--st-border-subtle)]">
            {cases.map(c => (
              <div
                key={c.id}
                className="px-4 py-3 flex items-center justify-between hover:bg-[color:var(--st-accent-dim)] transition-colors"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-[color:var(--st-accent)]">{c.caseId}</span>
                    <span className="text-sm text-[color:var(--st-text-primary)] truncate" title={c.caseName}>{c.caseName}</span>
                  </div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5 font-mono">
                    {new Date(c.createdAt).toLocaleDateString(undefined, {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </div>
                </div>
                {c.status && (
                  <span className="text-xs text-[color:var(--st-text-muted)] bg-[color:var(--st-accent-dim)] rounded-full px-2 py-0.5">
                    {c.status}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
