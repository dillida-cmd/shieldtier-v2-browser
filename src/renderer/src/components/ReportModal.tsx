import React, { useState, useEffect, useRef } from 'react';
import type { ReportFormat, ReportConfig, ReportPreview, ReportProgress, ReportResult, Screenshot, DOMSnapshot } from '../types';

interface TimelineEvent {
  time: string;
  event: string;
  detail: string;
  type: 'info' | 'warning' | 'danger' | 'success';
}

interface ReportModalProps {
  sessionId: string;
  sessionName: string;
  caseId: string;
  screenshots: Screenshot[];
  domSnapshots: DOMSnapshot[];
  timelineEvents: TimelineEvent[];
  captureStats: { harEntries: number; screenshots: number; domSnapshots: number };
  enrichmentCount: number;
  fileCount: number;
  onClose: () => void;
}

export function ReportModal({ sessionId, sessionName, caseId, screenshots, domSnapshots, timelineEvents, captureStats, enrichmentCount, fileCount, onClose }: ReportModalProps) {
  const defaultTitle = sessionName
    ? `${caseId ? caseId + ' — ' : ''}${sessionName} — Investigation Report`
    : 'ShieldTier Investigation Report';

  const [title, setTitle] = useState(defaultTitle);
  const [analystName, setAnalystName] = useState('');
  const [analystNotes, setAnalystNotes] = useState('');
  const [format, setFormat] = useState<ReportFormat>('html');
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState<ReportProgress | null>(null);
  const [result, setResult] = useState<ReportResult | null>(null);
  const pdfFrameRef = useRef<HTMLIFrameElement>(null);

  // Section toggles
  const [sections, setSections] = useState({
    networkAnalysis: true,
    iocIntelligence: true,
    fileAnalysis: true,
    visualEvidence: true,
    timeline: true,
  });

  // Options
  const [includeScreenshots, setIncludeScreenshots] = useState(true);
  const [includeDOMSnapshots, setIncludeDOMSnapshots] = useState(true);
  const [includeRawHAR, setIncludeRawHAR] = useState(true);

  // Load preview data and analyst profile
  useEffect(() => {
    (async () => {
      const [data, profile] = await Promise.all([
        window.shieldtier.report.preview(sessionId),
        window.shieldtier.config.getAnalystProfile(),
      ]);
      setPreview(data);
      if (profile?.name && !analystName) {
        setAnalystName(profile.name);
      }
    })();
  }, [sessionId]);

  // Listen for progress
  useEffect(() => {
    const unsub = window.shieldtier.report.onProgress((p) => {
      setProgress(p);
    });
    return () => { unsub(); };
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    setResult(null);
    setProgress({ stage: 'Collecting data...', percent: 10 });

    try {
      // Collect HAR data if network section enabled
      let harEntries: any[] = [];
      if (sections.networkAnalysis) {
        setProgress({ stage: 'Fetching network data...', percent: 20 });
        try {
          const har = await window.shieldtier.capture.getHAR(sessionId);
          harEntries = har?.log?.entries || [];
        } catch { /* no HAR available */ }
      }

      setProgress({ stage: 'Building report...', percent: 50 });

      // Build the report HTML client-side
      const html = buildReportHTML({
        title,
        analystName,
        analystNotes,
        caseId,
        sessionName,
        sections,
        includeScreenshots,
        includeDOMSnapshots,
        screenshots,
        domSnapshots,
        timelineEvents,
        harEntries,
        preview,
      });

      setProgress({ stage: 'Exporting...', percent: 80 });

      const baseName = caseId || 'report';

      if (format === 'json') {
        const jsonStr = JSON.stringify({
          title, analystName, analystNotes, caseId, sessionName,
          generatedAt: new Date().toISOString(),
          screenshots: includeScreenshots ? screenshots.map(s => ({ id: s.id, url: s.url, timestamp: s.timestamp })) : [],
          domSnapshots: includeDOMSnapshots ? domSnapshots.map(d => ({ id: d.id, url: d.url, timestamp: d.timestamp, html: d.html })) : [],
          timeline: timelineEvents,
          networkRequests: harEntries.length,
          harEntries: harEntries.slice(0, 500),
        }, null, 2);
        const saveRes = await (window.shieldtier.report as any).saveFile(jsonStr, `${baseName}-investigation.json`, 'json');
        if (saveRes?.cancelled) {
          setResult(null);
        } else {
          setResult({ success: true, filePath: saveRes?.filePath, fileSize: saveRes?.fileSize });
        }
      } else if (format === 'pdf') {
        // Inject into hidden iframe and trigger print dialog
        const iframe = pdfFrameRef.current;
        if (iframe) {
          const doc = iframe.contentDocument;
          if (doc) {
            doc.open();
            doc.write(html);
            doc.close();
            setTimeout(() => { iframe.contentWindow?.print(); }, 600);
          }
        }
        setResult({ success: true });
      } else {
        // HTML — show native save dialog, write to chosen path
        const saveRes = await (window.shieldtier.report as any).saveFile(html, `${baseName}-investigation.html`, 'html');
        if (saveRes?.cancelled) {
          setResult(null);
        } else {
          setResult({ success: true, filePath: saveRes?.filePath, fileSize: saveRes?.fileSize });
        }
      }

      setProgress({ stage: 'Done', percent: 100 });
    } catch (e: any) {
      setResult({ success: false, error: e?.message || 'Report generation failed' });
    } finally {
      setGenerating(false);
      setTimeout(() => setProgress(null), 500);
    }
  };


  const toggleSection = (key: keyof typeof sections) => {
    setSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatLabel = format === 'pdf' ? 'PDF' : format.toUpperCase();

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={onClose}>
      <div
        className="glass rounded-xl border w-[580px] max-w-[90vw]"
        onClick={e => e.stopPropagation()}
      >
        {/* Hidden iframe for PDF print */}
        <iframe ref={pdfFrameRef} className="hidden" title="pdf-print" />

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[color:var(--st-border-subtle)]">
          <div className="flex items-center gap-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--st-success)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            <span className="text-sm font-semibold text-[color:var(--st-text-primary)]">Generate Report</span>
          </div>
          <button onClick={onClose} className="text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] transition-colors cursor-pointer">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="overflow-y-auto px-5 py-4 space-y-4" style={{ maxHeight: 'calc(85vh - 110px)' }}>
          {/* Report Info */}
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Report Title</label>
              <input
                type="text"
                value={title}
                onChange={e => setTitle(e.target.value)}
                className="w-full glass-input border rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-blue-500"
                placeholder="Investigation Report"
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Analyst Name</label>
              <input
                type="text"
                value={analystName}
                onChange={e => setAnalystName(e.target.value)}
                className="w-full glass-input border rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-blue-500"
                placeholder="Your name"
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Analyst Notes</label>
              <textarea
                value={analystNotes}
                onChange={e => setAnalystNotes(e.target.value)}
                rows={3}
                className="w-full glass-input border rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-blue-500 resize-none"
                placeholder="Investigation findings, observations, recommendations..."
              />
            </div>
          </div>

          {/* Sections */}
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-2">Report Sections</label>
            <div className="space-y-1.5">
              <SectionCheckbox
                label="Network Analysis"
                count={captureStats.harEntries}
                countLabel="requests"
                checked={sections.networkAnalysis}
                onChange={() => toggleSection('networkAnalysis')}
              />
              <SectionCheckbox
                label="IOC Intelligence"
                count={enrichmentCount}
                countLabel="IOCs"
                checked={sections.iocIntelligence}
                onChange={() => toggleSection('iocIntelligence')}
              />
              <SectionCheckbox
                label="File Analysis"
                count={fileCount}
                countLabel="files"
                checked={sections.fileAnalysis}
                onChange={() => toggleSection('fileAnalysis')}
              />
              <SectionCheckbox
                label="Visual Evidence"
                count={captureStats.screenshots}
                countLabel={`screenshots, ${captureStats.domSnapshots} DOM snapshots`}
                checked={sections.visualEvidence}
                onChange={() => toggleSection('visualEvidence')}
              />
              <SectionCheckbox
                label="Timeline"
                count={timelineEvents.length}
                countLabel="events"
                checked={sections.timeline}
                onChange={() => toggleSection('timeline')}
              />
            </div>
          </div>

          {/* Options */}
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-2">Options</label>
            <div className="space-y-1.5">
              <OptionCheckbox
                label={`Include screenshots (${captureStats.screenshots})`}
                checked={includeScreenshots}
                onChange={setIncludeScreenshots}
                disabled={!sections.visualEvidence}
              />
              <OptionCheckbox
                label={`Include DOM snapshots (${captureStats.domSnapshots})`}
                checked={includeDOMSnapshots}
                onChange={setIncludeDOMSnapshots}
                disabled={!sections.visualEvidence}
              />
              {format === 'zip' && (
                <OptionCheckbox
                  label="Include raw HAR capture"
                  checked={includeRawHAR}
                  onChange={setIncludeRawHAR}
                />
              )}
            </div>
          </div>

          {/* Format Selector */}
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-2">Export Format</label>
            <div className="flex gap-2">
              <FormatButton
                label="HTML"
                description="Self-contained report"
                active={format === 'html'}
                onClick={() => setFormat('html')}
              />
              <FormatButton
                label="PDF"
                description="Print-ready report"
                active={format === 'pdf'}
                onClick={() => setFormat('pdf')}
              />
              <FormatButton
                label="JSON"
                description="Structured data"
                active={format === 'json'}
                onClick={() => setFormat('json')}
              />
              <FormatButton
                label="ZIP"
                description="Evidence package"
                active={format === 'zip'}
                onClick={() => setFormat('zip')}
              />
            </div>
          </div>

          {/* Preview Stats */}
          {preview && (
            <div className="bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded-lg p-3">
              <div className="text-xs text-[color:var(--st-text-muted)] mb-2">Session Overview</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <div>
                  <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{preview.networkRequests}</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)]">Requests</div>
                </div>
                <div>
                  <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{preview.uniqueDomains}</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)]">Domains</div>
                </div>
                <div>
                  <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{captureStats.screenshots}</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)]">Screenshots</div>
                </div>
                <div>
                  <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{captureStats.domSnapshots}</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)]">DOM Snaps</div>
                </div>
                {preview.iocTotal > 0 && (
                  <div>
                    <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{preview.iocTotal}</div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)]">IOCs</div>
                  </div>
                )}
                {preview.iocMalicious > 0 && (
                  <div>
                    <div className="text-lg font-bold text-red-400">{preview.iocMalicious}</div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)]">Malicious</div>
                  </div>
                )}
                {preview.filesAnalyzed > 0 && (
                  <div>
                    <div className="text-lg font-bold text-[color:var(--st-text-primary)]">{preview.filesAnalyzed}</div>
                    <div className="text-[10px] text-[color:var(--st-text-muted)]">Files</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Progress */}
          {generating && progress && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[color:var(--st-text-muted)]">{progress.stage}</span>
                <span className="text-[color:var(--st-text-muted)]">{progress.percent}%</span>
              </div>
              <div className="h-1.5 bg-[color:var(--st-bg-elevated)] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[color:var(--st-accent)] rounded-full transition-all duration-300"
                  role="progressbar"
                  aria-valuenow={progress.percent}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Report generation progress"
                  style={{ width: `${progress.percent}%` }}
                />
              </div>
            </div>
          )}

          {/* Result */}
          {result && (
            <div
              role="alert"
              className={`p-3 rounded-lg border text-sm ${
                result.success
                  ? 'bg-[color:var(--st-success-dim)] border-[color:var(--st-success)]/30 text-[color:var(--st-success)]'
                  : 'bg-[color:var(--st-danger-dim)] border-[color:var(--st-danger)]/30 text-[color:var(--st-danger)]'
              }`}
            >
              {result.success
                ? format === 'pdf'
                  ? 'Print dialog opened — select "Save as PDF" to export'
                  : `Report saved${result.filePath ? ' to ' + result.filePath : ''} (${formatSize(result.fileSize || 0)})`
                : `Error: ${result.error}`
              }
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-[color:var(--st-border-subtle)]">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] transition-colors cursor-pointer"
          >
            {result?.success ? 'Close' : 'Cancel'}
          </button>
          <button
            onClick={handleGenerate}
            disabled={generating || !title.trim()}
            className="px-4 py-1.5 text-xs bg-[color:var(--st-success)] hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            {generating ? (
              <>
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating...
              </>
            ) : (
              <>Generate {formatLabel}</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Report HTML Builder
// ═══════════════════════════════════════════════════════

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildReportHTML(opts: {
  title: string; analystName: string; analystNotes: string;
  caseId: string; sessionName: string;
  sections: { networkAnalysis: boolean; iocIntelligence: boolean; fileAnalysis: boolean; visualEvidence: boolean; timeline: boolean };
  includeScreenshots: boolean; includeDOMSnapshots: boolean;
  screenshots: Screenshot[]; domSnapshots: DOMSnapshot[];
  timelineEvents: { time: string; event: string; detail: string; type: string }[];
  harEntries: any[]; preview: ReportPreview | null;
}): string {
  const { title, analystName, analystNotes, caseId, sessionName, sections, includeScreenshots, includeDOMSnapshots, screenshots, domSnapshots, timelineEvents, harEntries, preview } = opts;
  const now = new Date().toLocaleString();

  let body = '';

  // Header
  body += `<div class="header">
    <h1>${esc(title)}</h1>
    <div class="meta">
      ${caseId ? `<span><strong>Case:</strong> ${esc(caseId)}</span>` : ''}
      ${sessionName ? `<span><strong>Investigation:</strong> ${esc(sessionName)}</span>` : ''}
      ${analystName ? `<span><strong>Analyst:</strong> ${esc(analystName)}</span>` : ''}
      <span><strong>Generated:</strong> ${esc(now)}</span>
    </div>
  </div>`;

  // Analyst Notes
  if (analystNotes.trim()) {
    body += `<div class="section"><h2>Analyst Notes</h2><p>${esc(analystNotes).replace(/\n/g, '<br>')}</p></div>`;
  }

  // Overview stats
  if (preview) {
    body += `<div class="section"><h2>Session Overview</h2><div class="stats">
      <div class="stat"><span class="stat-num">${preview.networkRequests}</span><span class="stat-label">Requests</span></div>
      <div class="stat"><span class="stat-num">${preview.uniqueDomains}</span><span class="stat-label">Domains</span></div>
      <div class="stat"><span class="stat-num">${screenshots.length}</span><span class="stat-label">Screenshots</span></div>
      <div class="stat"><span class="stat-num">${domSnapshots.length}</span><span class="stat-label">DOM Snapshots</span></div>
      ${preview.iocTotal > 0 ? `<div class="stat"><span class="stat-num">${preview.iocTotal}</span><span class="stat-label">IOCs</span></div>` : ''}
      ${preview.iocMalicious > 0 ? `<div class="stat"><span class="stat-num danger">${preview.iocMalicious}</span><span class="stat-label">Malicious</span></div>` : ''}
    </div></div>`;
  }

  // Network Analysis
  if (sections.networkAnalysis && harEntries.length > 0) {
    const domains = new Set(harEntries.map((e: any) => { try { return new URL(e.request?.url || '').hostname; } catch { return '?'; } }));
    body += `<div class="section"><h2>Network Analysis</h2>
      <p>${harEntries.length} requests across ${domains.size} domains</p>
      <table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Size</th></tr></thead><tbody>`;
    for (const e of harEntries.slice(0, 200)) {
      const r = e.request || {};
      const resp = e.response || {};
      const url = (r.url || '').length > 80 ? (r.url || '').slice(0, 80) + '...' : (r.url || '');
      const ct = (resp.content?.mimeType || '').split(';')[0];
      body += `<tr><td>${esc(r.method || '')}</td><td class="mono">${esc(url)}</td><td>${resp.status || ''}</td><td>${esc(ct)}</td><td>${resp.bodySize > 0 ? (resp.bodySize / 1024).toFixed(1) + ' KB' : '-'}</td></tr>`;
    }
    body += `</tbody></table>`;
    if (harEntries.length > 200) body += `<p class="muted">... and ${harEntries.length - 200} more requests</p>`;
    body += `</div>`;
  }

  // Timeline
  if (sections.timeline && timelineEvents.length > 0) {
    body += `<div class="section"><h2>Timeline</h2><table><thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead><tbody>`;
    for (const ev of timelineEvents) {
      body += `<tr><td class="mono">${esc(ev.time)}</td><td><span class="badge badge-${ev.type}">${esc(ev.event)}</span></td><td>${esc(ev.detail)}</td></tr>`;
    }
    body += `</tbody></table></div>`;
  }

  // Visual Evidence — Screenshots
  if (sections.visualEvidence && includeScreenshots && screenshots.length > 0) {
    body += `<div class="section"><h2>Screenshots (${screenshots.length})</h2><div class="screenshots">`;
    for (const ss of screenshots) {
      body += `<div class="screenshot">
        <img src="${ss.dataUrl}" alt="Screenshot" />
        <div class="caption">${esc(ss.url)} — ${new Date(ss.timestamp).toLocaleTimeString()}</div>
      </div>`;
    }
    body += `</div></div>`;
  }

  // Visual Evidence — DOM Snapshots
  if (sections.visualEvidence && includeDOMSnapshots && domSnapshots.length > 0) {
    body += `<div class="section"><h2>DOM Snapshots (${domSnapshots.length})</h2>`;
    for (const snap of domSnapshots) {
      body += `<div class="dom-snap">
        <div class="dom-header">${esc(snap.url)} — ${new Date(snap.timestamp).toLocaleTimeString()} — ${(snap.html.length / 1024).toFixed(1)} KB</div>
        <pre class="dom-code">${esc(snap.html.slice(0, 3000))}${snap.html.length > 3000 ? '\n\n... [truncated]' : ''}</pre>
      </div>`;
    }
    body += `</div>`;
  }

  // Footer
  body += `<div class="footer">Generated by ShieldTier SOC Browser &mdash; ${esc(now)}</div>`;

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0;background:#0f172a;padding:2rem;font-size:13px;line-height:1.6}
.header{border-bottom:2px solid #334155;padding-bottom:1.5rem;margin-bottom:2rem}
.header h1{font-size:1.5rem;font-weight:700;color:#f1f5f9;margin-bottom:0.5rem}
.meta{display:flex;flex-wrap:wrap;gap:1.5rem;font-size:12px;color:#94a3b8}
.meta strong{color:#cbd5e1}
.section{margin-bottom:2rem;page-break-inside:avoid}
.section h2{font-size:1rem;font-weight:600;color:#f1f5f9;margin-bottom:0.75rem;padding-bottom:0.25rem;border-bottom:1px solid #1e293b}
.section p{color:#cbd5e1;margin-bottom:0.5rem}
.stats{display:flex;flex-wrap:wrap;gap:1rem}
.stat{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:0.75rem 1.25rem;text-align:center;min-width:100px}
.stat-num{display:block;font-size:1.5rem;font-weight:700;color:#f1f5f9}
.stat-num.danger{color:#f87171}
.stat-label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.05em}
table{width:100%;border-collapse:collapse;font-size:11px;margin-top:0.5rem}
th{text-align:left;padding:6px 8px;border-bottom:2px solid #334155;color:#94a3b8;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:0.03em}
td{padding:5px 8px;border-bottom:1px solid #1e293b;color:#cbd5e1;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mono{font-family:'SF Mono',Menlo,monospace;font-size:10px}
.muted{color:#64748b;font-size:11px;margin-top:0.5rem}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600}
.badge-info{background:#1e3a5f;color:#60a5fa}
.badge-warning{background:#422006;color:#fbbf24}
.badge-danger{background:#450a0a;color:#f87171}
.badge-success{background:#052e16;color:#4ade80}
.screenshots{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
.screenshot{background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;page-break-inside:avoid}
.screenshot img{width:100%;display:block}
.caption{padding:6px 10px;font-size:10px;color:#94a3b8;font-family:monospace}
.dom-snap{background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;margin-bottom:1rem;page-break-inside:avoid}
.dom-header{padding:8px 12px;font-size:11px;color:#94a3b8;border-bottom:1px solid #334155;font-family:monospace}
.dom-code{padding:10px 12px;font-size:10px;color:#64748b;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-family:'SF Mono',Menlo,monospace}
.footer{margin-top:3rem;padding-top:1rem;border-top:1px solid #1e293b;text-align:center;font-size:10px;color:#475569}
@media print{body{background:#fff;color:#1e293b;padding:1cm}
.header h1{color:#0f172a}.section h2{color:#0f172a}.stat{border-color:#e2e8f0}.stat-num{color:#0f172a}
td,th{border-color:#e2e8f0;color:#334155}th{color:#64748b}
.dom-snap,.screenshot{border-color:#e2e8f0}.dom-header{color:#64748b;border-color:#e2e8f0}
.dom-code{color:#475569}.caption{color:#64748b}.footer{color:#94a3b8;border-color:#e2e8f0}
.stats .stat{background:#f8fafc}table{page-break-inside:auto}tr{page-break-inside:avoid}}
</style></head><body>${body}</body></html>`;
}

// ═══════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════

function SectionCheckbox({ label, count, countLabel, checked, onChange }: {
  label: string;
  count: number;
  countLabel: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <label className="flex items-center gap-2 cursor-pointer group">
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        className="w-3.5 h-3.5 rounded border-[color:var(--st-text-muted)] bg-[color:var(--st-bg-panel)] text-blue-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
      />
      <span className={`text-xs ${checked ? 'text-[color:var(--st-text-primary)]' : 'text-[color:var(--st-text-muted)]'}`}>{label}</span>
      <span className="text-[10px] text-[color:var(--st-text-muted)]">
        ({count.toLocaleString()} {countLabel})
      </span>
    </label>
  );
}

function OptionCheckbox({ label, checked, onChange, disabled }: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className={`flex items-center gap-2 ${disabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}`}>
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        disabled={disabled}
        className="w-3.5 h-3.5 rounded border-[color:var(--st-text-muted)] bg-[color:var(--st-bg-panel)] text-blue-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
      />
      <span className="text-xs text-[color:var(--st-text-muted)]">{label}</span>
    </label>
  );
}

function FormatButton({ label, description, active, onClick }: {
  label: string;
  description: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 px-3 py-2 rounded-lg border text-center transition-colors cursor-pointer ${
        active
          ? 'bg-blue-600/20 border-blue-500/40 text-blue-400'
          : 'glass-input border text-[color:var(--st-text-muted)] hover:border-[color:var(--st-text-muted)]'
      }`}
    >
      <div className="text-xs font-semibold">{label}</div>
      <div className="text-[10px] opacity-60">{description}</div>
    </button>
  );
}
