// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Body Tab
// ---------------------------------------------------------------------------

import React, { useState } from 'react';
import type { ParsedEmail } from './email-types';
import { htmlToText } from './email-utils';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';

export function BodyTab({ email }: { email: ParsedEmail }) {
  const [showSource, setShowSource] = useState(false);

  const readableText = email.htmlBody ? htmlToText(email.htmlBody) : '';
  const hasHtml = !!email.htmlBody;
  const hasText = !!email.textBody;

  return (
    <div className="space-y-3">
      {/* Readable content — prefer HTML-extracted text, fallback to text body */}
      {(readableText || hasText) && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <h4 className="text-[color:var(--st-text-muted)] text-[10px]">
              {hasHtml ? 'Email Content' : 'Text Body'}
            </h4>
            {hasHtml && (
              <Button
                onClick={() => setShowSource(!showSource)}
                variant="ghost"
                size="sm"
                className="text-[9px] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] h-6 px-1.5"
              >
                {showSource ? 'Show Readable' : 'View HTML Source'}
              </Button>
            )}
          </div>

          {showSource ? (
            <ScrollArea className="max-h-[500px]">
              <pre className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-3 text-[10px] text-[color:var(--st-text-muted)] font-mono whitespace-pre-wrap">
                {email.htmlBody}
              </pre>
            </ScrollArea>
          ) : (
            <ScrollArea className="max-h-[500px]">
              <pre className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-3 text-[11px] text-[color:var(--st-text-secondary)] whitespace-pre-wrap leading-relaxed" style={{ fontFamily: 'system-ui, -apple-system, sans-serif' }}>
                {readableText || email.textBody}
              </pre>
            </ScrollArea>
          )}
        </div>
      )}

      {/* Show text body separately only if both exist and they differ significantly */}
      {hasHtml && hasText && readableText !== email.textBody && (
        <div>
          <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Plain Text Alternative</h4>
          <pre className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-3 text-[11px] text-[color:var(--st-text-secondary)] whitespace-pre-wrap max-h-60 overflow-y-auto leading-relaxed" style={{ fontFamily: 'system-ui, -apple-system, sans-serif' }}>
            {email.textBody}
          </pre>
        </div>
      )}

      {!readableText && !hasText && (
        <div className="text-[color:var(--st-text-muted)] text-sm py-8 text-center">No body content</div>
      )}
    </div>
  );
}
