// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Phishing Score Card (Overview tab content)
// ---------------------------------------------------------------------------

import React from 'react';
import type { ParsedEmail } from './email-types';
import {
  getScoreColor,
  getScoreBg,
  getVerdictLabel,
  getSeverityColor,
  getAuthBadge,
  htmlToText,
} from './email-utils';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';
import { ScrollArea } from '../ui/scroll-area';

export function PhishingScoreCard({ email }: { email: ParsedEmail }) {
  return (
    <div className="space-y-4">
      {/* Risk Score */}
      {email.phishingScore && (
        <Card className={`p-3 ${getScoreBg(email.phishingScore.score)}`}>
          <CardContent className="p-0">
            <div className="flex items-center gap-3">
              <div className={`text-3xl font-bold font-mono ${getScoreColor(email.phishingScore.score)}`}>
                {email.phishingScore.score}
              </div>
              <div>
                <Badge
                  variant={email.phishingScore.verdict === 'likely_phishing' ? 'destructive' : email.phishingScore.verdict === 'suspicious' ? 'warning' : 'success'}
                >
                  {getVerdictLabel(email.phishingScore.verdict)}
                </Badge>
                <div className="text-[color:var(--st-text-muted)] text-[10px] mt-1">
                  {email.phishingScore.indicators.length} indicator{email.phishingScore.indicators.length !== 1 ? 's' : ''} detected
                </div>
              </div>
            </div>
            {/* Score breakdown */}
            <div className="flex gap-3 mt-2 text-[10px]">
              {Object.entries(email.phishingScore.breakdown)
                .filter(([, v]) => v > 0)
                .map(([cat, val]) => (
                <span key={cat} className="text-[color:var(--st-text-muted)]">
                  {cat}: <span className="text-[color:var(--st-text-secondary)] font-mono">{val}</span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key headers */}
      <div className="space-y-1">
        <div className="flex"><span className="text-[color:var(--st-text-muted)] w-16">From:</span><span className="text-[color:var(--st-text-primary)] flex-1 font-mono">{email.from}</span></div>
        <div className="flex"><span className="text-[color:var(--st-text-muted)] w-16">To:</span><span className="text-[color:var(--st-text-primary)] flex-1 font-mono">{email.to.join(', ')}</span></div>
        {email.cc.length > 0 && (
          <div className="flex"><span className="text-[color:var(--st-text-muted)] w-16">CC:</span><span className="text-[color:var(--st-text-primary)] flex-1 font-mono">{email.cc.join(', ')}</span></div>
        )}
        <div className="flex"><span className="text-[color:var(--st-text-muted)] w-16">Subject:</span><span className="text-[color:var(--st-text-primary)] flex-1">{email.subject}</span></div>
        <div className="flex"><span className="text-[color:var(--st-text-muted)] w-16">Date:</span><span className="text-[color:var(--st-text-primary)] flex-1 font-mono">{email.date}</span></div>
      </div>

      {/* Auth badges */}
      {email.authentication.length > 0 && (
        <div>
          <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Authentication</h4>
          <div className="flex gap-2">
            {email.authentication.map((auth, i) => {
              const pass = auth.result.toLowerCase().includes('pass');
              const fail = auth.result.toLowerCase().includes('fail');
              return (
                <Badge key={i} variant={pass ? 'success' : fail ? 'destructive' : 'warning'} size="sm">
                  {auth.method.toUpperCase()}: {auth.result}
                </Badge>
              );
            })}
          </div>
        </div>
      )}

      {/* Spoofing alerts */}
      {email.phishingScore && email.phishingScore.indicators
        .filter(ind => ind.severity === 'critical' || ind.severity === 'high')
        .map(ind => (
          <div key={ind.id} className={`p-2 rounded border ${getSeverityColor(ind.severity)} bg-opacity-10`}>
            <div className="flex items-center gap-1.5">
              <span className={`text-[9px] px-1 rounded ${getSeverityColor(ind.severity)}`}>{ind.severity}</span>
              {ind.mitre && (
                <span className="text-[9px] px-1 rounded bg-purple-600/20 text-purple-400 font-mono">{ind.mitre}</span>
              )}
              <span className="text-[color:var(--st-text-primary)]">{ind.description}</span>
            </div>
            <div className="text-[color:var(--st-text-muted)] text-[10px] mt-0.5">{ind.evidence}</div>
          </div>
        ))}

      {/* Email body content */}
      {(email.htmlBody || email.textBody) && (
        <div>
          <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Content</h4>
          <ScrollArea className="max-h-[400px]">
            <pre className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-3 text-[11px] text-[color:var(--st-text-secondary)] whitespace-pre-wrap leading-relaxed" style={{ fontFamily: 'system-ui, -apple-system, sans-serif' }}>
              {email.htmlBody ? htmlToText(email.htmlBody) : email.textBody}
            </pre>
          </ScrollArea>
        </div>
      )}
    </div>
  );
}
