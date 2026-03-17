// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Attachments Tab
// ---------------------------------------------------------------------------

import React, { useState, useEffect } from 'react';
import type { ParsedEmail, FileAnalysisResult } from './email-types';
import { getRiskColor, formatSize } from './email-utils';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card } from '../ui/card';

// ═══════════════════════════════════════════════════════════════════════════
// Network Activity (outgoing communications from sandbox)
// ═══════════════════════════════════════════════════════════════════════════

function NetworkActivity({ network }: { network: any }) {
  const httpRequests = network?.httpRequests || network?.http || [];
  const dnsQueries = network?.dnsQueries || network?.dns || [];
  const connections = network?.connections || [];

  const hasAny = httpRequests.length > 0 || dnsQueries.length > 0 || connections.length > 0;
  if (!hasAny) return null;

  return (
    <div className="mt-2 space-y-1.5">
      <div className="text-[9px] text-[color:var(--st-text-muted)] uppercase flex items-center gap-1.5">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>
        Outgoing Communications
      </div>

      {/* DNS queries */}
      {dnsQueries.length > 0 && (
        <div className="bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border)] p-1.5">
          <div className="text-[9px] text-[color:var(--st-text-muted)] mb-1">DNS ({dnsQueries.length})</div>
          {dnsQueries.map((dns: any, i: number) => (
            <div key={i} className="text-[10px] font-mono text-yellow-400 truncate" title={typeof dns === 'string' ? dns : dns.query || dns.domain}>
              {typeof dns === 'string' ? dns : dns.query || dns.domain || JSON.stringify(dns)}
            </div>
          ))}
        </div>
      )}

      {/* HTTP requests */}
      {httpRequests.length > 0 && (
        <div className="bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border)] p-1.5">
          <div className="text-[9px] text-[color:var(--st-text-muted)] mb-1">HTTP ({httpRequests.length})</div>
          {httpRequests.map((req: any, i: number) => (
            <div key={i} className="text-[10px] flex items-center gap-1.5 truncate">
              <span className="text-cyan-400 font-mono shrink-0">{req.method || 'GET'}</span>
              <span className="text-[color:var(--st-text-secondary)] font-mono truncate" title={typeof req === 'string' ? req : req.url || req.uri}>
                {typeof req === 'string' ? req : req.url || req.uri || JSON.stringify(req)}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Raw connections */}
      {connections.length > 0 && httpRequests.length === 0 && (
        <div className="bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border)] p-1.5">
          <div className="text-[9px] text-[color:var(--st-text-muted)] mb-1">Connections ({connections.length})</div>
          {connections.map((conn: any, i: number) => (
            <div key={i} className="text-[10px] font-mono text-[color:var(--st-text-secondary)] truncate">
              {typeof conn === 'string' ? conn : `${conn.dst || conn.ip || ''}:${conn.port || ''} (${conn.protocol || 'tcp'})`}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// File Metadata Section (PDF pages, PE info, Office macros, etc.)
// ═══════════════════════════════════════════════════════════════════════════

function FileMetadataSection({ metadata, fileType }: { metadata: Record<string, any>; fileType: string }) {
  const sections: { label: string; items: [string, string][] }[] = [];

  // PDF metadata
  if (metadata.pdf || fileType.toLowerCase().includes('pdf')) {
    const pdf = metadata.pdf || metadata;
    const items: [string, string][] = [];
    if (pdf.pages !== undefined) items.push(['Pages', String(pdf.pages)]);
    if (pdf.title) items.push(['Title', pdf.title]);
    if (pdf.author) items.push(['Author', pdf.author]);
    if (pdf.creator) items.push(['Creator', pdf.creator]);
    if (pdf.producer) items.push(['Producer', pdf.producer]);
    if (pdf.hasJavaScript) items.push(['JavaScript', 'Yes — potentially malicious']);
    if (pdf.hasAutoAction) items.push(['Auto-Action', 'Yes — opens automatically']);
    if (pdf.embeddedFiles) items.push(['Embedded Files', String(pdf.embeddedFiles)]);
    if (pdf.urls && pdf.urls.length > 0) items.push(['URLs Found', String(pdf.urls.length)]);
    if (items.length > 0) sections.push({ label: 'PDF Analysis', items });
  }

  // PE metadata
  if (metadata.peCapability || metadata.pe || fileType.toLowerCase().includes('executable')) {
    const pe = metadata.peCapability || metadata.pe || metadata;
    const items: [string, string][] = [];
    if (pe.arch) items.push(['Architecture', pe.arch]);
    if (pe.subsystem) items.push(['Subsystem', pe.subsystem]);
    if (pe.imports) items.push(['Imports', Array.isArray(pe.imports) ? pe.imports.join(', ') : String(pe.imports)]);
    if (pe.sections) items.push(['Sections', Array.isArray(pe.sections) ? pe.sections.map((s: any) => s.name || s).join(', ') : String(pe.sections)]);
    if (pe.signed !== undefined) items.push(['Signed', pe.signed ? 'Yes' : 'No']);
    if (items.length > 0) sections.push({ label: 'PE Analysis', items });
  }

  // Script detonation
  if (metadata.detonation) {
    const det = metadata.detonation;
    const items: [string, string][] = [];
    if (det.scriptType) items.push(['Script Type', det.scriptType]);
    if (det.operations) items.push(['Operations', String(det.operations.length || det.operations)]);
    if (det.verdict) items.push(['Verdict', det.verdict]);
    if (items.length > 0) sections.push({ label: 'Script Detonation', items });
  }

  if (sections.length === 0) return null;

  return (
    <>
      {sections.map(sec => (
        <div key={sec.label}>
          <div className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1">{sec.label}</div>
          <div className="bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border)] divide-y divide-[color:var(--st-border)]">
            {sec.items.map(([label, value]) => (
              <div key={label} className="flex px-2 py-1 gap-2">
                <span className="text-[10px] text-[color:var(--st-text-muted)] shrink-0 w-28">{label}</span>
                <span className={`text-[10px] font-mono break-all flex-1 ${
                  value.includes('malicious') || value.includes('Yes') ? 'text-red-400' : 'text-[color:var(--st-text-secondary)]'
                }`}>{value}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Attachments Tab
// ═══════════════════════════════════════════════════════════════════════════

export function AttachmentsTab({ email, sessionId }: { email: ParsedEmail; sessionId: string }) {
  const [fileResults, setFileResults] = useState<Map<string, FileAnalysisResult>>(new Map());
  const [expandedAtt, setExpandedAtt] = useState<string | null>(null);
  const [analyzingIds, setAnalyzingIds] = useState<Set<string>>(new Set());

  // Fetch file analysis results for each attachment
  useEffect(() => {
    async function fetchResults() {
      const results = new Map<string, FileAnalysisResult>();
      for (const att of email.attachments) {
        if (att.quarantineFileId) {
          try {
            const file = await window.shieldtier.fileanalysis.getFile(sessionId, att.quarantineFileId);
            if (file) results.set(att.quarantineFileId, file);
          } catch {}
        }
      }
      setFileResults(results);
    }
    fetchResults();
  }, [email.attachments, sessionId]);

  // Listen for file analysis updates
  useEffect(() => {
    const unsub = window.shieldtier.fileanalysis.onFileUpdate((_sid: string, file: FileAnalysisResult) => {
      setFileResults(prev => {
        const next = new Map(prev);
        next.set(file.id, file);
        return next;
      });
      // Clear analyzing state when done
      if (file.status === 'complete' || file.status === 'error') {
        setAnalyzingIds(prev => {
          const next = new Set(prev);
          next.delete(file.id);
          return next;
        });
      }
    });
    return () => { unsub(); };
  }, []);

  const handleAnalyzeBehavior = async (fileId: string) => {
    setAnalyzingIds(prev => new Set(prev).add(fileId));
    try {
      await window.shieldtier.fileanalysis.analyzeBehavior(sessionId, fileId);
    } catch {
      setAnalyzingIds(prev => {
        const next = new Set(prev);
        next.delete(fileId);
        return next;
      });
    }
  };

  if (email.attachments.length === 0) {
    return <div className="text-[color:var(--st-text-muted)] text-sm py-8 text-center">No attachments</div>;
  }

  return (
    <div className="space-y-3">
      <h4 className="text-[color:var(--st-text-muted)] text-[10px]">
        Attachments ({email.attachments.length})
        {email.attachments.some(a => a.quarantineFileId) && (
          <span className="ml-2 text-cyan-400">&middot; Routed through File Analysis</span>
        )}
      </h4>

      {email.attachments.map(att => {
        const fileResult = att.quarantineFileId ? fileResults.get(att.quarantineFileId) : null;
        const isExpanded = expandedAtt === att.id;
        const risk = fileResult ? getRiskColor(fileResult.riskLevel) : getRiskColor('info');
        const isAnalyzing = att.quarantineFileId ? analyzingIds.has(att.quarantineFileId) : false;
        const hasBehavioral = fileResult?.behavioralAnalysisDone;
        const sb = fileResult?.sandboxResults?.[0];

        return (
          <div key={att.id} className={`rounded border ${fileResult ? risk.border : 'border-[color:var(--st-border)]'} bg-[color:var(--st-bg-panel)] overflow-hidden`}>
            {/* Attachment header — always visible */}
            <button
              onClick={() => setExpandedAtt(isExpanded ? null : att.id)}
              className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-[color:var(--st-bg-panel)] transition-colors"
            >
              {/* File icon with risk dot */}
              <div className="relative flex-shrink-0">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[color:var(--st-text-muted)]">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
                {fileResult && (
                  <div className={`absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ${risk.dot} ${fileResult.riskLevel === 'critical' ? 'animate-pulse' : ''}`} />
                )}
              </div>

              {/* File info */}
              <div className="flex-1 min-w-0">
                <div className="text-[color:var(--st-text-primary)] truncate text-xs">{att.filename}</div>
                <div className="text-[color:var(--st-text-muted)] text-[10px] flex items-center gap-2">
                  <span>{att.contentType}</span>
                  <span>&middot;</span>
                  <span className="font-mono">{formatSize(att.size)}</span>
                  {fileResult?.staticAnalysis?.fileType && (
                    <>
                      <span>&middot;</span>
                      <span className="text-[color:var(--st-text-muted)]">{fileResult.staticAnalysis.fileType}</span>
                    </>
                  )}
                </div>
              </div>

              {/* Status badges */}
              <div className="flex items-center gap-1.5 flex-shrink-0">
                {fileResult && (
                  <Badge
                    variant={fileResult.riskLevel === 'critical' || fileResult.riskLevel === 'high' ? 'destructive' : fileResult.riskLevel === 'medium' ? 'warning' : 'outline'}
                    size="sm"
                    className="uppercase"
                  >
                    {fileResult.riskLevel}
                  </Badge>
                )}
                {sb?.verdict && (
                  <Badge
                    variant={sb.verdict === 'malicious' ? 'destructive' : sb.verdict === 'suspicious' ? 'warning' : 'success'}
                    size="sm"
                  >
                    {sb.verdict}
                  </Badge>
                )}
                {fileResult?.status === 'analyzing' && (
                  <div className="animate-spin w-3 h-3 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full" />
                )}
                {/* Expand chevron */}
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={`text-[color:var(--st-text-muted)] transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>
            </button>

            {/* Expanded analysis detail */}
            {isExpanded && fileResult && (
              <div className="border-t border-[color:var(--st-border)] px-3 py-2.5 space-y-3">
                {/* Hashes */}
                {fileResult.hashes && (
                  <div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1">Hashes</div>
                    <div className="bg-[color:var(--st-bg-base)] rounded border border-[color:var(--st-border)] divide-y divide-[color:var(--st-border)]">
                      {(['sha256', 'md5', 'sha1'] as const).map(algo => (
                        <div key={algo} className="flex items-center px-2 py-1 gap-2">
                          <span className="text-[10px] text-[color:var(--st-text-muted)] uppercase w-12 shrink-0">{algo}</span>
                          <span className="text-[10px] text-[color:var(--st-text-secondary)] font-mono truncate flex-1" title={fileResult.hashes![algo]}>
                            {fileResult.hashes![algo]}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Static analysis findings */}
                {fileResult.staticAnalysis && fileResult.staticAnalysis.findings.length > 0 && (
                  <div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1">
                      Findings ({fileResult.staticAnalysis.findings.length})
                    </div>
                    <div className="space-y-1">
                      {fileResult.staticAnalysis.findings.map((f, i) => {
                        const fColor = getRiskColor(f.severity);
                        return (
                          <div key={i} className="flex items-start gap-2 py-1">
                            <span className={`text-[9px] px-1 py-0.5 rounded shrink-0 mt-0.5 uppercase font-medium ${fColor.bg} ${fColor.text}`}>
                              {f.severity.slice(0, 4)}
                            </span>
                            <div className="flex-1 min-w-0">
                              <span className="text-[10px] text-[color:var(--st-text-secondary)]">{f.description}</span>
                              {f.mitre && (
                                <span className="text-[9px] text-purple-400 ml-1.5 font-mono">{f.mitre}</span>
                              )}
                              <div className="text-[9px] text-[color:var(--st-text-muted)]">{f.category}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Entropy */}
                {fileResult.staticAnalysis && (
                  <div className="flex items-center gap-4 text-[10px]">
                    <span className="text-[color:var(--st-text-muted)]">Entropy:</span>
                    <div className="flex items-center gap-1.5 flex-1">
                      <div className="flex-1 h-1.5 bg-[color:var(--st-bg-elevated)] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${fileResult.staticAnalysis.entropy > 7 ? 'bg-red-500' : fileResult.staticAnalysis.entropy > 5 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${(fileResult.staticAnalysis.entropy / 8) * 100}%` }}
                        />
                      </div>
                      <span className={`font-mono ${fileResult.staticAnalysis.entropy > 7 ? 'text-red-400' : 'text-[color:var(--st-text-secondary)]'}`}>
                        {fileResult.staticAnalysis.entropy.toFixed(2)}
                      </span>
                    </div>
                  </div>
                )}

                {/* Behavioral / Sandbox results */}
                {sb && sb.status === 'complete' && (
                  <div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)] uppercase tracking-wider font-medium mb-1">Behavioral Analysis</div>
                    <div className={`rounded border p-2 ${
                      sb.verdict === 'malicious' ? 'border-red-500/30 bg-red-500/5' :
                      sb.verdict === 'suspicious' ? 'border-yellow-500/30 bg-yellow-500/5' :
                      'border-green-500/30 bg-green-500/5'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-sm font-bold uppercase ${
                          sb.verdict === 'malicious' ? 'text-red-400' : sb.verdict === 'suspicious' ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {sb.verdict}
                        </span>
                        {sb.score !== undefined && (
                          <span className="text-lg font-mono font-bold text-[color:var(--st-text-primary)]">{sb.score}<span className="text-[color:var(--st-text-muted)] text-xs">/100</span></span>
                        )}
                      </div>

                      {/* Signatures */}
                      {sb.details?.signatures && (sb.details.signatures as any[]).length > 0 && (
                        <div className="space-y-1 mt-2">
                          <div className="text-[9px] text-[color:var(--st-text-muted)] uppercase">Signatures</div>
                          {(sb.details.signatures as any[]).map((sig: any, i: number) => (
                            <div key={i} className="flex items-start gap-1.5 text-[10px]">
                              <span className={`px-1 py-0.5 rounded text-[9px] shrink-0 ${
                                sig.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                sig.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                'bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-muted)]'
                              }`}>{sig.severity || 'info'}</span>
                              <span className="text-[color:var(--st-text-secondary)]">{sig.name}</span>
                              {sig.mitre && <span className="text-purple-400 font-mono text-[9px]">{sig.mitre}</span>}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Network activity */}
                      {sb.details?.network && (
                        <NetworkActivity network={sb.details.network} />
                      )}

                      {/* Advanced findings (detonation results) */}
                      {sb.details?.advancedFindings && (sb.details.advancedFindings as any[]).length > 0 && (
                        <div className="space-y-1 mt-2">
                          <div className="text-[9px] text-[color:var(--st-text-muted)] uppercase">Advanced Findings</div>
                          {(sb.details.advancedFindings as any[]).map((af: any, i: number) => (
                            <div key={i} className="flex items-start gap-1.5 text-[10px]">
                              <span className={`px-1 py-0.5 rounded text-[9px] shrink-0 ${getRiskColor(af.severity).bg} ${getRiskColor(af.severity).text}`}>
                                {(af.severity || 'info').slice(0, 4)}
                              </span>
                              <span className="text-[color:var(--st-text-secondary)]">{af.description}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Static metadata — PDF, PE, Office, etc. */}
                {fileResult.staticAnalysis?.metadata && (
                  <FileMetadataSection metadata={fileResult.staticAnalysis.metadata} fileType={fileResult.staticAnalysis.fileType} />
                )}

                {/* Analyze button */}
                {fileResult.status === 'complete' && !hasBehavioral && !isAnalyzing && (
                  <Button
                    onClick={() => handleAnalyzeBehavior(fileResult.id)}
                    variant="outline"
                    size="sm"
                    className="w-full border-cyan-500/30 bg-cyan-600/10 text-cyan-400 hover:bg-cyan-600/20"
                  >
                    Run Behavioral Analysis
                  </Button>
                )}
                {isAnalyzing && (
                  <div className="flex items-center justify-center gap-2 py-1.5 text-[10px] text-cyan-400">
                    <div className="animate-spin w-3 h-3 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full" />
                    Analyzing behavior...
                  </div>
                )}
              </div>
            )}

            {/* Expanded but no file result yet */}
            {isExpanded && !fileResult && att.extracted && (
              <div className="border-t border-[color:var(--st-border)] px-3 py-3 text-center text-[color:var(--st-text-muted)] text-[10px]">
                <div className="animate-spin w-3.5 h-3.5 border-2 border-[color:var(--st-text-muted)] border-t-[color:var(--st-text-secondary)] rounded-full mx-auto mb-1.5" />
                Loading analysis results...
              </div>
            )}
            {isExpanded && !fileResult && !att.extracted && (
              <div className="border-t border-[color:var(--st-border)] px-3 py-3 text-center text-[color:var(--st-text-muted)] text-[10px]">
                Attachment not extracted — file analysis unavailable
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
