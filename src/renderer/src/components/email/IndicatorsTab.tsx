// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Indicators Tab
// ---------------------------------------------------------------------------

import React from 'react';
import type { PhishingIndicator, PhishingScore } from './email-types';
import { getSeverityColor } from './email-utils';
import { Badge } from '../ui/badge';

export function IndicatorsTab({ phishingScore }: { phishingScore: PhishingScore }) {
  // Group by category
  const grouped: Record<string, PhishingIndicator[]> = {};
  for (const ind of phishingScore.indicators) {
    if (!grouped[ind.category]) grouped[ind.category] = [];
    grouped[ind.category].push(ind);
  }

  return (
    <div>
      <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-2">
        Phishing Indicators ({phishingScore.indicators.length})
      </h4>
      {Object.entries(grouped).map(([category, inds]) => (
        <div key={category} className="mb-3">
          <div className="text-[color:var(--st-text-muted)] text-[10px] uppercase tracking-wider mb-1">{category} ({inds.length})</div>
          <div className="space-y-1">
            {inds.map(ind => (
              <div key={ind.id} className="p-2 rounded border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)]">
                <div className="flex items-center gap-1.5">
                  <Badge
                    variant={ind.severity === 'critical' || ind.severity === 'high' ? 'destructive' : ind.severity === 'medium' ? 'warning' : 'outline'}
                    size="sm"
                  >
                    {ind.severity}
                  </Badge>
                  {ind.mitre && (
                    <Badge variant="purple" size="sm" className="font-mono">{ind.mitre}</Badge>
                  )}
                  <span className="text-[color:var(--st-text-primary)]">{ind.description}</span>
                </div>
                <div className="text-[color:var(--st-text-muted)] text-[10px] mt-0.5 font-mono">{ind.evidence}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
