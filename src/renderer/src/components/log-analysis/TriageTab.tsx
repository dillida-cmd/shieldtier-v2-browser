// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Triage Tab
// ---------------------------------------------------------------------------

import React, { useState } from 'react';
import type { Severity, LogTriage } from './log-analysis-types';
import { getSeverityBadge, getPhaseColor } from './log-analysis-utils';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../ui/table';

export function TriageTab({ triage }: { triage: LogTriage }) {
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());

  const toggleSection = (key: string) => {
    setCollapsedSections(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const entitySections: { key: keyof LogTriage['entities']; label: string; showInternal?: boolean }[] = [
    { key: 'users', label: 'Users' },
    { key: 'ips', label: 'Private IPs', showInternal: true },
    { key: 'externalIps', label: 'Public IPs' },
    { key: 'hosts', label: 'Hosts' },
    { key: 'processes', label: 'Processes' },
    { key: 'commands', label: 'Suspicious Commands' },
  ];

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Incident severity card */}
      <Card className="rounded-lg p-4">
        <CardContent className="flex items-center gap-4">
          <div>
            <p className="text-xs text-[color:var(--st-text-muted)] mb-1">Incident Severity</p>
            <Badge
              size="sm"
              className={cn('font-bold uppercase', getSeverityBadge(triage.incident.severity))}
            >
              {triage.incident.severity}
            </Badge>
          </div>
          <div className="flex-1">
            <p className="text-xs text-[color:var(--st-text-muted)] mb-1">Score</p>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-2 bg-[color:var(--st-accent-dim)] rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full transition-all',
                    triage.incident.score >= 80 ? 'bg-red-500' :
                    triage.incident.score >= 60 ? 'bg-orange-500' :
                    triage.incident.score >= 40 ? 'bg-yellow-500' :
                    'bg-green-500'
                  )}
                  style={{ width: `${triage.incident.score}%` }}
                />
              </div>
              <span className="text-sm font-bold text-[color:var(--st-text-primary)] font-mono">{triage.incident.score}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Entity sections */}
      {entitySections.map(({ key, label }) => {
        const entities = triage.entities[key];
        if (!entities || entities.length === 0) return null;
        const isCollapsed = collapsedSections.has(key);

        return (
          <div key={key}>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleSection(key)}
              className="flex items-center gap-2 w-full justify-start px-0 h-auto py-1 mb-2"
            >
              <svg
                width="10" height="10" viewBox="0 0 24 24" fill="currentColor"
                className={cn('text-[color:var(--st-text-muted)] transition-transform', !isCollapsed && 'rotate-90')}
              >
                <path d="M8 5v14l11-7z" />
              </svg>
              <span className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">
                {label}
              </span>
              <span className="text-[10px] text-[color:var(--st-text-muted)]">({entities.length})</span>
            </Button>

            {!isCollapsed && (
              key === 'commands' ? (
                <div className="space-y-1">
                  {entities.map((ent, i) => (
                    <Card key={i} className="rounded-lg p-2">
                      <CardContent>
                        <div className="flex items-center gap-2 mb-1">
                          <Badge
                            size="sm"
                            className={cn('text-[9px] font-bold uppercase', getSeverityBadge(ent.severity))}
                          >
                            {ent.severity}
                          </Badge>
                          <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono">{ent.count}x</span>
                        </div>
                        <pre className="text-[10px] text-[color:var(--st-text-secondary)] font-mono bg-[color:var(--st-bg-base)] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
                          {ent.value}
                        </pre>
                        {ent.context && (
                          <p className="text-[10px] text-[color:var(--st-text-muted)] mt-1">{ent.context}</p>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <Card className="rounded-lg overflow-hidden p-0">
                  <Table className="text-[11px]">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="px-3 py-1.5 h-auto text-[11px]">Value</TableHead>
                        <TableHead className="px-2 py-1.5 w-14 h-auto text-[11px]">Count</TableHead>
                        <TableHead className="px-2 py-1.5 w-16 h-auto text-[11px]">Severity</TableHead>
                        <TableHead className="px-2 py-1.5 h-auto text-[11px]">Context</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {entities.map((ent, i) => (
                        <TableRow key={i}>
                          <TableCell className="px-3 py-1.5 text-[color:var(--st-text-primary)] font-mono">{ent.value}</TableCell>
                          <TableCell className="px-2 py-1.5 text-[color:var(--st-text-muted)] font-mono">{ent.count}</TableCell>
                          <TableCell className="px-2 py-1.5">
                            <Badge
                              size="sm"
                              className={cn('text-[9px] font-bold uppercase', getSeverityBadge(ent.severity))}
                            >
                              {ent.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="px-2 py-1.5 text-[color:var(--st-text-muted)] break-words">{ent.context}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              )
            )}
          </div>
        );
      })}

      {/* Attack chain */}
      {triage.attackChain.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Attack Chain
          </h3>
          <div className="flex items-center gap-1 flex-wrap">
            {triage.attackChain.map((phase, i) => (
              <React.Fragment key={phase.phase}>
                {i > 0 && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-[color:var(--st-text-muted)] shrink-0">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                )}
                <Badge
                  size="sm"
                  variant="outline"
                  className={cn('rounded font-medium', getPhaseColor(phase.phase))}
                  title={`${phase.events} events: ${phase.indicators.join(', ')}`}
                >
                  {phase.phase.replace(/-/g, ' ')}
                  <span className="ml-1 opacity-60 font-mono">({phase.events})</span>
                </Badge>
              </React.Fragment>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
