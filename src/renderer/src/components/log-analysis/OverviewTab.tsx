// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Overview Tab
// ---------------------------------------------------------------------------

import React from 'react';
import type { Severity, LogAnalysisResult } from './log-analysis-types';
import { SEVERITY_DOT, INSIGHT_BORDER, getVerdictStyle } from './log-analysis-utils';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';

export function OverviewTab({ analysis }: { analysis: LogAnalysisResult }) {
  const v = analysis.verdict;
  const vStyle = v ? getVerdictStyle(v.verdict) : null;

  return (
    <div className="space-y-4 max-w-3xl">
      {/* Verdict banner */}
      {v && vStyle && (
        <Card className={`p-4 ${vStyle.bg} ${vStyle.border}`}>
          <div className="flex items-center gap-4">
            <Badge
              variant={v.verdict === 'clean' ? 'success' : v.verdict === 'suspicious' ? 'warning' : 'destructive'}
              className="text-lg font-bold px-3 py-1"
            >
              {v.verdict.charAt(0).toUpperCase() + v.verdict.slice(1)}
            </Badge>
            <div className="flex-1">
              {/* Confidence bar */}
              <div className="flex items-center gap-2 text-xs text-[color:var(--st-text-muted)] mb-1">
                Confidence
                <span className={`font-bold ${vStyle.text}`}>{v.confidence}%</span>
              </div>
              <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    v.verdict === 'clean' ? 'bg-green-500' :
                    v.verdict === 'suspicious' ? 'bg-yellow-500' :
                    v.verdict === 'compromised' ? 'bg-orange-500' :
                    'bg-red-500'
                  }`}
                  style={{ width: `${v.confidence}%` }}
                />
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3">
        <Card className="p-3 text-center">
          <p className="text-lg font-bold text-[color:var(--st-text-primary)] font-mono">{analysis.eventCount.toLocaleString()}</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)]">Events</p>
        </Card>
        <Card className="p-3 text-center">
          <p className="text-lg font-bold text-[color:var(--st-text-primary)]">{analysis.format}</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)]">Format</p>
        </Card>
        <Card className="p-3 text-center">
          <p className="text-lg font-bold text-[color:var(--st-text-primary)] font-mono">{analysis.parseErrors}</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)]">Parse Errors</p>
        </Card>
        <Card className="p-3">
          {/* Severity bars */}
          <div className="space-y-0.5">
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(sev => {
              const count = analysis.severityCounts[sev];
              const pct = analysis.eventCount > 0 ? (count / analysis.eventCount) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-1">
                  <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[sev]}`} />
                  <span className="text-[9px] text-[color:var(--st-text-muted)] w-10">{sev}</span>
                  <div className="flex-1 h-1 bg-[color:var(--st-accent-dim)] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${SEVERITY_DOT[sev]}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[9px] text-[color:var(--st-text-muted)] w-8 text-right font-mono">{count}</span>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* Insights */}
      {analysis.insights.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider mb-2">
            Insights
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {analysis.insights.map((insight, i) => (
              <Card
                key={i}
                className={`border-l-4 p-3 ${
                  INSIGHT_BORDER[insight.level] || INSIGHT_BORDER.info
                }`}
              >
                <p className="text-xs text-[color:var(--st-text-primary)] font-medium">{insight.title}</p>
                <p className="text-[11px] text-[color:var(--st-text-muted)] mt-0.5">{insight.detail}</p>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
