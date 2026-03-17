// ---------------------------------------------------------------------------
// ShieldTier Email Panel — URLs Tab
// ---------------------------------------------------------------------------

import React from 'react';
import type { ParsedEmail } from './email-types';
import { Badge } from '../ui/badge';

export function URLsTab({ email }: { email: ParsedEmail }) {
  return (
    <div>
      <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-2">Extracted URLs ({email.urls.length})</h4>
      {email.urls.length === 0 ? (
        <div className="text-[color:var(--st-text-muted)] text-sm py-8 text-center">No URLs found</div>
      ) : (
        <div className="space-y-1">
          {email.urls.map((u, i) => {
            const isFinal = u.displayText.startsWith('[FINAL DESTINATION');
            const isHop = u.displayText.startsWith('[redirect hop');
            const isUnwrapped = u.displayText.startsWith('[unwrapped from');
            const isError = !!u.redirectError;
            const isChainEntry = isFinal || isHop || isUnwrapped;
            return (
              <div
                key={i}
                className={`p-2 rounded border ${
                  isError ? 'border-orange-500/30 bg-orange-600/5' :
                  isFinal ? 'border-red-500/40 bg-red-600/10' :
                  isHop ? 'border-yellow-500/20 bg-yellow-600/5 ml-4' :
                  isUnwrapped ? 'border-purple-500/30 bg-purple-600/5 ml-4' :
                  u.mismatch ? 'border-red-500/30 bg-red-600/5' :
                  'border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)]'
                }`}
              >
                <div className="flex items-center gap-2">
                  {isFinal && (
                    <Badge variant="destructive" size="sm">FINAL DEST</Badge>
                  )}
                  {isHop && (
                    <Badge variant="warning" size="sm">HOP</Badge>
                  )}
                  {isUnwrapped && (
                    <Badge variant="purple" size="sm">UNWRAPPED</Badge>
                  )}
                  {isError && (
                    <Badge variant="warning" size="sm" className="bg-orange-500/15 text-orange-400">FAILED</Badge>
                  )}
                  {u.mismatch && !isChainEntry && !isError && (
                    <Badge variant="destructive" size="sm">MISMATCH</Badge>
                  )}
                  <Badge variant={u.source === 'html' ? 'default' : 'outline'} size="sm">
                    {u.source}
                  </Badge>
                </div>
                <div className={`font-mono text-[10px] mt-0.5 break-all ${isFinal ? 'text-red-400 font-medium' : isError ? 'text-orange-400' : 'text-cyan-400'}`}>
                  {u.url}
                </div>
                {u.displayText && u.displayText !== u.url && (
                  <div className="text-[10px] mt-0.5">
                    {isChainEntry || isError ? (
                      <span className={isFinal ? 'text-red-400/70' : isError ? 'text-orange-400/70' : 'text-yellow-400/60'}>{u.displayText}</span>
                    ) : (
                      <span className="text-[color:var(--st-text-muted)]">Display: <span className={u.mismatch ? 'text-red-400' : 'text-[color:var(--st-text-secondary)]'}>{u.displayText}</span></span>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
