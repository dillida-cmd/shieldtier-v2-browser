// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Investigation Tab
// ---------------------------------------------------------------------------

import React, { useMemo } from 'react';
import type { Severity, NormalizedEvent, LogInvestigation } from './log-analysis-types';
import {
  SEVERITY_DOT,
  CHAIN_TYPE_ICONS,
  getSeverityBadge,
  formatTimestamp,
  extractRootEntity,
  extractHost,
  extractUser,
  extractNetworkSummary,
  buildProcessTree,
  computeTreeDepth,
  countTreeNodes,
  aggregateEvents,
} from './log-analysis-utils';
import { ProcessTreeNodeView } from './ProcessTreeView';
import { EmptySection } from './EmptySection';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';

// ═══════════════════════════════════════════════════════════════════════════
// Aggregated Timeline — deduplicates repetitive events in investigation chains
// ═══════════════════════════════════════════════════════════════════════════

function AggregatedTimeline({ events }: { events: NormalizedEvent[] }) {
  const groups = useMemo(() => aggregateEvents(events), [events]);

  return (
    <div className="border-t border-[color:var(--st-border-subtle)] px-4 py-3 bg-[color:var(--st-bg-base)]">
      <div className="border-l border-[color:var(--st-border-subtle)] ml-1 pl-4 space-y-0">
        {groups.map((grp, gIdx) => (
          <div key={gIdx} className="relative py-1.5">
            <div className="absolute -left-[17px] top-3 w-2 h-px bg-[color:var(--st-border-subtle)]" />
            <div className="flex items-start gap-2">
              <span className={cn('w-1.5 h-1.5 rounded-full mt-1 shrink-0', SEVERITY_DOT[grp.severity])} />
              <div className="flex-1 min-w-0">
                <div className="text-[11px] text-[color:var(--st-text-secondary)] break-words">
                  {grp.message}
                  {grp.count > 1 && (
                    <Badge size="sm" variant="outline" className="ml-2 text-[9px] text-[color:var(--st-text-muted)] font-mono">
                      x{grp.count}
                    </Badge>
                  )}
                </div>
                <div className="text-[10px] text-[color:var(--st-text-muted)] font-mono mt-0.5">
                  {grp.count > 1 ? (
                    <>{formatTimestamp(grp.firstTs)} — {formatTimestamp(grp.lastTs)}</>
                  ) : (
                    formatTimestamp(grp.firstTs)
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Investigation Tab
// ═══════════════════════════════════════════════════════════════════════════

export function InvestigationTab({
  investigation,
  expandedChains,
  onToggleChain,
}: {
  investigation: LogInvestigation;
  expandedChains: Set<number>;
  onToggleChain: (idx: number) => void;
}) {
  if (investigation.chains.length === 0) {
    return <EmptySection message="No investigation chains found" />;
  }

  return (
    <div className="space-y-2 max-w-4xl">
      <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
        Investigation Chains ({investigation.chains.length})
      </h3>

      {investigation.chains.map((chain, idx) => {
        const isExpanded = expandedChains.has(idx);
        const iconPath = CHAIN_TYPE_ICONS[chain.type] || CHAIN_TYPE_ICONS.file_access;
        const rootEntity = extractRootEntity(chain);
        const host = extractHost(chain);
        const user = extractUser(chain);
        const netSummary = chain.type === 'network' ? extractNetworkSummary(chain) : '';

        // Build tree for process chains
        const tree = chain.type === 'process' ? buildProcessTree(chain.events) : [];
        const depth = chain.type === 'process' ? computeTreeDepth(tree) : 0;
        const nodeCount = chain.type === 'process' ? countTreeNodes(tree) : chain.events.length;

        return (
          <Card key={idx} className="rounded-lg overflow-hidden p-0">
            {/* Card header */}
            <Button
              variant="ghost"
              onClick={() => onToggleChain(idx)}
              className="w-full px-3 py-2.5 h-auto text-left justify-start rounded-none"
            >
              <div className="w-full">
                <div className="flex items-center gap-3">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" className="text-[color:var(--st-text-muted)] shrink-0">
                    <path d={iconPath} />
                  </svg>
                  <div className="flex-1 min-w-0">
                    <span className="text-xs text-[color:var(--st-text-primary)] font-medium font-mono">
                      {rootEntity}
                      {host && <span className="text-[color:var(--st-text-muted)] font-mono"> on {host}</span>}
                    </span>
                  </div>
                  <Badge
                    size="sm"
                    className={cn('text-[9px] font-bold uppercase', getSeverityBadge(chain.severity))}
                  >
                    {chain.severity}
                  </Badge>
                  <svg
                    width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    strokeWidth="2"
                    className={cn('text-[color:var(--st-text-muted)] transition-transform', isExpanded && 'rotate-180')}
                  >
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </div>
                <div className="flex items-center gap-3 mt-1 ml-7 text-[10px] text-[color:var(--st-text-muted)]">
                  {chain.type === 'process' && <span>Depth: {depth}</span>}
                  {chain.type === 'process' && <span>|</span>}
                  {chain.type === 'network' && netSummary && <><span className="font-mono">{netSummary}</span><span>|</span></>}
                  <span>{chain.events.length} event{chain.events.length !== 1 ? 's' : ''}</span>
                  {user && <><span>|</span><span>User: <span className="font-mono">{user}</span></span></>}
                </div>
              </div>
            </Button>

            {/* Expanded body */}
            {isExpanded && chain.type === 'process' && tree.length > 0 && (
              <CardContent className="border-t border-[color:var(--st-border-subtle)] px-4 py-3 bg-[color:var(--st-bg-base)]">
                <div className="text-[10px] font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">Process Tree</div>
                {tree.map((root, i) => (
                  <ProcessTreeNodeView key={i} node={root} depth={0} />
                ))}
              </CardContent>
            )}

            {/* Timeline view for non-process chains */}
            {isExpanded && chain.type !== 'process' && (
              <AggregatedTimeline events={chain.events} />
            )}
          </Card>
        );
      })}
    </div>
  );
}
