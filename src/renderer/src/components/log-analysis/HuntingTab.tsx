// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Hunting Tab (YARA-like threat detection matches)
// ---------------------------------------------------------------------------

import React, { useState, useMemo } from 'react';
import type { HuntingQueryResult } from './log-analysis-types';
import { getSeverityBadge, truncate } from './log-analysis-utils';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';

export function HuntingTab({ hunting }: { hunting: HuntingQueryResult[] }) {
  const [expandedQuery, setExpandedQuery] = useState<string | null>(null);

  // Sort by severity (critical first), then by match count
  const sorted = useMemo(() => {
    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...hunting].sort((a, b) => {
      const sa = sevOrder[a.query.severity] ?? 4;
      const sb = sevOrder[b.query.severity] ?? 4;
      if (sa !== sb) return sa - sb;
      return b.matchCount - a.matchCount;
    });
  }, [hunting]);

  const totalMatches = hunting.reduce((sum, h) => sum + h.matchCount, 0);
  const criticalCount = hunting.filter(h => h.query.severity === 'critical').length;
  const highCount = hunting.filter(h => h.query.severity === 'high').length;

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Summary banner */}
      <Card className={cn(
        'rounded-lg p-4',
        criticalCount > 0 ? 'bg-red-500/10 border-red-500/30' :
        highCount > 0 ? 'bg-orange-500/10 border-orange-500/30' :
        'bg-blue-500/10 border-blue-500/30'
      )}>
        <CardContent className="flex items-center gap-3">
          <div className={cn(
            'text-lg font-bold font-mono',
            criticalCount > 0 ? 'text-red-400' :
            highCount > 0 ? 'text-orange-400' :
            'text-blue-400'
          )}>
            {hunting.length}
          </div>
          <div>
            <p className={cn(
              'text-sm font-bold',
              criticalCount > 0 ? 'text-red-400' :
              highCount > 0 ? 'text-orange-400' :
              'text-blue-400'
            )}>
              Hunting {hunting.length === 1 ? 'Query' : 'Queries'} Matched
            </p>
            <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">
              <span className="font-mono">{totalMatches}</span> total event {totalMatches === 1 ? 'match' : 'matches'} across <span className="font-mono">{hunting.length}</span> detection {hunting.length === 1 ? 'rule' : 'rules'}
              {criticalCount > 0 && ` \u00b7 ${criticalCount} critical`}
              {highCount > 0 && ` \u00b7 ${highCount} high`}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Query results */}
      <div className="space-y-2">
        {sorted.map((result) => {
          const isExpanded = expandedQuery === result.query.id;
          return (
            <Card key={result.query.id} className="rounded-lg overflow-hidden p-0">
              {/* Query header (clickable) */}
              <Button
                variant="ghost"
                onClick={() => setExpandedQuery(isExpanded ? null : result.query.id)}
                className="w-full h-auto px-3 py-3 text-left justify-start rounded-none"
              >
                <div className="w-full flex items-start gap-3">
                  <Badge
                    size="sm"
                    className={cn('shrink-0 text-[9px] font-bold uppercase', getSeverityBadge(result.query.severity))}
                  >
                    {result.query.severity}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-[color:var(--st-text-primary)] font-medium">{result.query.name}</p>
                    <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">{result.query.description}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge size="sm" variant="purple" className="font-mono">
                      {result.query.mitre}
                    </Badge>
                    <Badge size="sm" variant="outline" className="font-mono">
                      {result.matchCount}
                    </Badge>
                    <svg
                      width="12" height="12" viewBox="0 0 24 24" fill="none"
                      stroke="currentColor" strokeWidth="2"
                      className={cn('text-[color:var(--st-text-muted)] transition-transform', isExpanded && 'rotate-180')}
                    >
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </div>
                </div>
              </Button>

              {/* Expanded: show matched evidence */}
              {isExpanded && (
                <CardContent className="border-t border-[color:var(--st-border)] bg-[color:var(--st-bg-base)] p-3 space-y-1.5">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge size="sm" variant="outline" className="text-[color:var(--st-text-muted)]">
                      {result.query.category.replace(/-/g, ' ')}
                    </Badge>
                    <span className="text-[10px] text-[color:var(--st-text-muted)]">{result.query.source}</span>
                    <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono">{result.query.id}</span>
                  </div>
                  {result.matches.map((match, i) => (
                    <div key={i} className="rounded border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)] p-2">
                      <p className="text-[10px] text-[color:var(--st-text-secondary)] font-mono truncate" title={match.evidence}>
                        {truncate(match.evidence, 120)}
                      </p>
                      <div className="flex items-center gap-3 mt-1 text-[9px] text-[color:var(--st-text-muted)]">
                        <span className="font-mono">{match.event.timestamp}</span>
                        <span className="font-mono">{match.event.eventType}</span>
                      </div>
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
