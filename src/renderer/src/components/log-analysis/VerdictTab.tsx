// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Verdict Tab
// ---------------------------------------------------------------------------

import React from 'react';
import type { LogVerdict } from './log-analysis-types';
import { getSeverityBadge, getVerdictStyle, getPhaseColor } from './log-analysis-utils';
import { cn } from '../../lib/utils';
import { Badge } from '../ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Separator } from '../ui/separator';

export function VerdictTab({ verdict }: { verdict: LogVerdict }) {
  const vStyle = getVerdictStyle(verdict.verdict);

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Conviction meter */}
      <Card className={cn('rounded-lg p-5', vStyle.bg, vStyle.border)}>
        <CardContent className="flex items-center gap-4">
          <div className={cn('text-3xl font-bold', vStyle.text)}>
            {verdict.verdict.charAt(0).toUpperCase() + verdict.verdict.slice(1)}
          </div>
          <div className="flex-1">
            <div className="flex items-center justify-between text-xs text-[color:var(--st-text-muted)] mb-1">
              <span>Conviction</span>
              <span className={cn('font-bold font-mono', vStyle.text)}>{verdict.confidence}%</span>
            </div>
            <div className="w-full h-2.5 bg-white/10 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full transition-all duration-500',
                  verdict.verdict === 'clean' ? 'bg-green-500' :
                  verdict.verdict === 'suspicious' ? 'bg-yellow-500' :
                  verdict.verdict === 'compromised' ? 'bg-orange-500' :
                  'bg-red-500'
                )}
                style={{ width: `${verdict.confidence}%` }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Signals */}
      {verdict.signals.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Signals ({verdict.signals.length})
          </h3>
          <div className="space-y-1">
            {verdict.signals.map((sig, i) => (
              <Card key={i} className="rounded-lg p-3">
                <CardContent className="flex items-start gap-3">
                  <Badge
                    size="sm"
                    className={cn('shrink-0 text-[9px] font-bold uppercase', getSeverityBadge(sig.severity))}
                  >
                    {sig.severity}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-[color:var(--st-text-primary)]">{sig.title}</p>
                    <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5 font-mono">{sig.evidence}</p>
                  </div>
                  {sig.mitre && (
                    <Badge size="sm" variant="purple" className="shrink-0 font-mono">
                      {sig.mitre}
                    </Badge>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      <Separator />

      {/* Kill chain */}
      {verdict.killChain.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Kill Chain Progression
          </h3>
          <div className="flex items-center gap-1 flex-wrap">
            {verdict.killChain.map((phase, i) => (
              <React.Fragment key={phase}>
                {i > 0 && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-[color:var(--st-text-muted)] shrink-0">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                )}
                <Badge
                  size="sm"
                  variant="outline"
                  className={cn('rounded font-medium', getPhaseColor(phase))}
                >
                  {phase.replace(/-/g, ' ')}
                </Badge>
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* False positives */}
      {verdict.falsePositives.length > 0 && (
        <div>
          <Separator className="mb-4" />
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Possible False Positives
          </h3>
          <div className="space-y-1">
            {verdict.falsePositives.map((fp, i) => (
              <Card key={i} className="rounded-lg p-2">
                <CardContent className="flex items-center gap-2 text-[11px]">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-yellow-500 shrink-0">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  <span className="text-[color:var(--st-text-muted)]">{fp}</span>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Reasoning */}
      {verdict.reasoning && (
        <div>
          <Separator className="mb-4" />
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Reasoning
          </h3>
          <Card className="rounded-lg p-4">
            <CardContent>
              <p className="text-xs text-[color:var(--st-text-secondary)] leading-relaxed whitespace-pre-wrap">
                {verdict.reasoning}
              </p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
