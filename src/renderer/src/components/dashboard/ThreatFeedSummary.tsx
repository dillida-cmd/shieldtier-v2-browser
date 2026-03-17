import React, { useEffect, useState } from 'react';
import type { FeedMatcherStats } from '../../types';

export function ThreatFeedSummary() {
  const [stats, setStats] = useState<FeedMatcherStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const result = await window.shieldtier.threatfeed.getStats();
        setStats(result);
      } catch {
        // Silently fail
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div>
        <h3 className="text-xs font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-3">
          Threat Intelligence
        </h3>
        <div className="glass rounded-xl border p-4" aria-label="Loading" role="status">
          <div className="h-10 rounded-lg bg-[color:var(--st-border-subtle)] shimmer" />
        </div>
      </div>
    );
  }

  const feedNames = stats ? Object.keys(stats.feedBreakdown) : [];
  const totalIOCs = stats?.totalIOCs || 0;

  return (
    <div>
      <h3 className="text-xs font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-3">
        Threat Intelligence
      </h3>
      <div className="glass rounded-xl border p-4">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-lg bg-[color:var(--st-danger)]/10 flex items-center justify-center shrink-0">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[color:var(--st-danger)]" aria-label="Threat feed status">
              <path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/>
            </svg>
          </div>
          <div>
            <div className="text-xl font-bold text-[color:var(--st-text-primary)] font-mono">{totalIOCs.toLocaleString()}</div>
            <div className="text-xs text-[color:var(--st-text-muted)]">Total IOCs loaded</div>
          </div>
        </div>

        {feedNames.length > 0 ? (
          <div className="space-y-1.5 pt-3 border-t border-[color:var(--st-border-subtle)]">
            {feedNames.map(name => (
              <div key={name} className="flex items-center justify-between text-xs">
                <span className="text-[color:var(--st-text-secondary)] truncate">{name}</span>
                <span className="font-mono text-[color:var(--st-text-muted)]">{stats!.feedBreakdown[name].toLocaleString()}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[color:var(--st-text-muted)] opacity-50">No feeds configured</p>
        )}
      </div>
    </div>
  );
}
