// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Headers Tab
// ---------------------------------------------------------------------------

import React, { useState } from 'react';
import type { ParsedEmail } from './email-types';
import {
  HEADER_GROUPS,
  getHeaderHint,
  formatHeaderValue,
} from './email-utils';
import { Badge } from '../ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../ui/table';

// ═══════════════════════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════════════════════

/** ? icon with hover tooltip explaining the header. */
function HeaderHintIcon({ hint }: { hint: string }) {
  const [show, setShow] = useState(false);
  return (
    <span className="relative inline-flex">
      <span
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        className="w-3.5 h-3.5 rounded-full bg-amber-500/20 text-amber-400 text-[8px] font-bold flex items-center justify-center cursor-help shrink-0"
      >
        ?
      </span>
      {show && (
        <div className="absolute left-5 top-0 z-50 w-64 px-2.5 py-1.5 rounded bg-[color:var(--st-bg-elevated)] border border-amber-500/30 shadow-lg shadow-black/40">
          <p className="text-[10px] text-amber-200/90 leading-snug">{hint}</p>
        </div>
      )}
    </span>
  );
}

/** Renders opaque/encrypted header blobs with explanation instead of raw dump. */
function OpaqueHeaderValue({ headerKey, value, hint }: { headerKey: string; value: string; hint: string | null }) {
  const [expanded, setExpanded] = useState(false);
  const byteSize = Math.round(value.replace(/\s/g, '').length * 0.75); // base64 -> bytes approx

  return (
    <div className="flex-1 min-w-0">
      <div className="flex items-center gap-2">
        <span className="text-[color:var(--st-text-muted)] text-[10px] italic">
          Encrypted blob ({byteSize > 1024 ? `${(byteSize / 1024).toFixed(1)} KB` : `${byteSize} bytes`}) — not human-readable
        </span>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-[9px] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-muted)] underline"
        >
          {expanded ? 'hide raw' : 'show raw'}
        </button>
      </div>
      {hint && (
        <div className="text-[9px] text-amber-400/50 mt-0.5">{hint}</div>
      )}
      {expanded && (
        <div className="mt-1 p-1.5 bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border-subtle)] max-h-24 overflow-y-auto">
          <span className="text-[color:var(--st-text-muted)] text-[9px] font-mono break-all">{value}</span>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Headers Tab
// ═══════════════════════════════════════════════════════════════════════════

export function HeadersTab({ email }: { email: ParsedEmail }) {
  const headers = email.headers;
  const headerKeys = Object.keys(headers);

  // Categorize headers into groups
  const grouped: { label: string; color: string; entries: [string, string][] }[] = [];
  const used = new Set<string>();

  for (const group of HEADER_GROUPS) {
    const entries: [string, string][] = [];
    for (const key of group.keys) {
      // Case-insensitive match
      const match = headerKeys.find(k => k.toLowerCase() === key);
      if (match && headers[match]) {
        entries.push([match, headers[match]]);
        used.add(match);
      }
    }
    if (entries.length > 0) {
      grouped.push({ label: group.label, color: group.color, entries });
    }
  }

  // Collect X-headers and remaining headers
  const xHeaders: [string, string][] = [];
  const otherHeaders: [string, string][] = [];
  for (const key of headerKeys) {
    if (used.has(key)) continue;
    if (key.toLowerCase().startsWith('x-')) {
      xHeaders.push([key, headers[key]]);
    } else {
      otherHeaders.push([key, headers[key]]);
    }
    used.add(key);
  }
  if (xHeaders.length > 0) {
    grouped.push({ label: 'X-Headers', color: 'border-gray-500/40', entries: xHeaders });
  }
  if (otherHeaders.length > 0) {
    grouped.push({ label: 'Other', color: 'border-gray-600/40', entries: otherHeaders });
  }

  // Authentication results summary
  const auth = email.authentication;
  const spf = auth.find(a => a.method === 'spf');
  const dkim = auth.find(a => a.method === 'dkim');
  const dmarc = auth.find(a => a.method === 'dmarc');

  // Spoofing check: compare From vs Reply-To
  const fromAddr = (headers['from'] || headers['From'] || '').match(/<([^>]+)>/)?.[1] || headers['from'] || headers['From'] || '';
  const replyTo = (headers['reply-to'] || headers['Reply-To'] || '').match(/<([^>]+)>/)?.[1] || headers['reply-to'] || headers['Reply-To'] || '';
  const hasSpoofRisk = replyTo && fromAddr && replyTo.toLowerCase() !== fromAddr.toLowerCase();

  return (
    <div className="space-y-4">
      {/* Authentication Summary */}
      {auth.length > 0 && (
        <div>
          <h4 className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1.5">Authentication Results</h4>
          <div className="flex items-center gap-2 flex-wrap">
            {[
              { label: 'SPF', data: spf },
              { label: 'DKIM', data: dkim },
              { label: 'DMARC', data: dmarc },
            ].map(({ label, data }) => {
              if (!data) return (
                <div key={label} className="flex items-center gap-1.5 bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] px-2 py-1">
                  <span className="text-[10px] text-[color:var(--st-text-muted)] font-medium">{label}</span>
                  <Badge variant="outline" size="sm">none</Badge>
                </div>
              );
              const pass = data.result.toLowerCase().includes('pass');
              const fail = data.result.toLowerCase().includes('fail') || data.result.toLowerCase().includes('softfail');
              return (
                <div key={label} className={`flex items-center gap-1.5 bg-[color:var(--st-bg-panel)] rounded border px-2 py-1 ${
                  pass ? 'border-green-500/30' : fail ? 'border-red-500/30' : 'border-yellow-500/30'
                }`}>
                  <span className="text-[10px] text-[color:var(--st-text-secondary)] font-medium">{label}</span>
                  <Badge variant={pass ? 'success' : fail ? 'destructive' : 'warning'} size="sm">
                    {data.result}
                  </Badge>
                  {data.domain && <span className="text-[9px] text-[color:var(--st-text-muted)] font-mono">{data.domain}</span>}
                </div>
              );
            })}
          </div>
          {/* Spoofing warning */}
          {hasSpoofRisk && (
            <div className="mt-2 rounded border border-orange-500/30 bg-orange-500/10 px-2.5 py-1.5 text-[10px]">
              <span className="text-orange-400 font-medium">Possible Spoofing: </span>
              <span className="text-[color:var(--st-text-secondary)]">From ({fromAddr}) does not match Reply-To ({replyTo})</span>
            </div>
          )}
        </div>
      )}

      {/* Received Chain */}
      {email.receivedChain.length > 0 && (
        <div>
          <h4 className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1.5">
            Received Chain ({email.receivedChain.length} hops)
          </h4>
          <div className="space-y-1">
            {email.receivedChain.map((hop, i) => (
              <div key={i} className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-2 text-[10px]">
                <div className="flex items-start gap-2">
                  <span className="text-[color:var(--st-text-muted)] font-mono shrink-0 w-4 text-right">#{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[color:var(--st-text-secondary)]">
                      from <span className="text-cyan-400 font-mono">{hop.from || '\u2014'}</span>
                    </div>
                    <div className="text-[color:var(--st-text-secondary)]">
                      by <span className="text-cyan-400 font-mono">{hop.by || '\u2014'}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {hop.ip && (
                      <span className="px-1.5 py-0.5 rounded bg-yellow-500/15 text-yellow-400 font-mono text-[9px]">{hop.ip}</span>
                    )}
                    {hop.delay > 0 && (
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium ${
                        hop.delay > 300 ? 'bg-red-500/15 text-red-400' : hop.delay > 30 ? 'bg-orange-500/15 text-orange-400' : 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-muted)]'
                      }`}>
                        +{hop.delay > 60 ? `${Math.round(hop.delay / 60)}m` : `${Math.round(hop.delay)}s`}
                      </span>
                    )}
                  </div>
                </div>
                {hop.timestamp > 0 && (
                  <div className="ml-6 mt-0.5 text-[9px] text-[color:var(--st-text-muted)] font-mono">{new Date(hop.timestamp).toLocaleString()}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Grouped Headers */}
      {grouped.map((group) => (
        <div key={group.label}>
          <h4 className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1.5">{group.label}</h4>
          <div className={`bg-[color:var(--st-bg-panel)] rounded border-l-2 ${group.color} border border-[color:var(--st-border)] overflow-hidden`}>
            <Table>
              <TableBody>
                {group.entries.map(([key, val]) => {
                  const hint = getHeaderHint(key);
                  const { decoded, structured, opaque } = formatHeaderValue(key, val);
                  return (
                    <TableRow key={key} className="border-[color:var(--st-border)]">
                      <TableCell className="py-1.5 px-2 w-48 align-top">
                        <div className="flex items-center gap-1">
                          <span className="text-cyan-400 text-[10px] font-mono truncate" title={key}>{key}</span>
                          {hint && <HeaderHintIcon hint={hint} />}
                        </div>
                      </TableCell>
                      <TableCell className="py-1.5 px-2 align-top">
                        {opaque ? (
                          <OpaqueHeaderValue headerKey={key} value={decoded !== val ? decoded : val} hint={hint} />
                        ) : structured ? (
                          <div className="min-w-0">
                            <div className="grid gap-0.5">
                              {structured.map((field, fi) => (
                                <div key={fi} className="flex items-start gap-1.5 text-[10px]">
                                  <span className="text-purple-400 font-mono shrink-0 font-medium">{field.key}</span>
                                  {field.value && <span className="text-[color:var(--st-text-secondary)] font-mono">{field.value}</span>}
                                  {field.hint && <span className="text-amber-400/60 text-[9px]">&mdash; {field.hint}</span>}
                                </div>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <span className="text-[color:var(--st-text-secondary)] text-[10px] font-mono break-all">
                            {decoded !== val ? decoded : val}
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </div>
      ))}
    </div>
  );
}
