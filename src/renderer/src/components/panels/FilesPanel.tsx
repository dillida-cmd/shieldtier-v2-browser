/**
 * FilesPanel — File analysis, quarantine, sandbox results, enrichment cards.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import React, { useState, useEffect, useRef } from 'react';
import type { InvestigationSession, QuarantinedFile, EnrichmentResult } from '../../types';
import { RISK_COLORS } from '../analysis-helpers';
import MITREMappingTab from '../MITREMappingTab';
import {
  VERDICT_COLORS, PROVIDER_LABELS, STATUS_LABELS,
  formatFileSize,
} from './panel-utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/tabs';
import { Separator } from '../ui/separator';
import { cn } from '../../lib/utils';

// ═══════════════════════════════════════════════════════
// Risk level → Badge variant mapping
// ═══════════════════════════════════════════════════════

function riskBadgeVariant(riskLevel: string): 'destructive' | 'warning' | 'success' | 'outline' {
  switch (riskLevel) {
    case 'critical':
    case 'high':
      return 'destructive';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'success';
    default:
      return 'outline';
  }
}

// ═══════════════════════════════════════════════════════
// FilesPanel
// ═══════════════════════════════════════════════════════

export function FilesPanel({ session, files }: { session: InvestigationSession; files: Map<string, QuarantinedFile> }) {
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);

  const fileList = Array.from(files.values()).sort((a, b) => {
    // Critical/high first, then by creation time
    const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
    const ra = riskOrder[a.riskLevel] ?? 5;
    const rb = riskOrder[b.riskLevel] ?? 5;
    if (ra !== rb) return ra - rb;
    return b.createdAt - a.createdAt;
  });

  const selectedFile = selectedFileId ? files.get(selectedFileId) : null;

  // Summary counts
  const counts = {
    total: fileList.length,
    critical: fileList.filter(f => f.riskLevel === 'critical').length,
    high: fileList.filter(f => f.riskLevel === 'high').length,
    analyzing: fileList.filter(f => f.status !== 'complete' && f.status !== 'error').length,
  };

  const handleDelete = async (fileId: string) => {
    await window.shieldtier.fileanalysis.deleteFile(session.id, fileId);
    if (selectedFileId === fileId) setSelectedFileId(null);
  };

  const handleResubmit = async (fileId: string) => {
    await window.shieldtier.fileanalysis.resubmit(session.id, fileId);
  };

  const handleAnalyzeBehavior = async (fileId: string) => {
    await window.shieldtier.fileanalysis.analyzeBehavior(session.id, fileId);
  };

  const handleUpload = async () => {
    await window.shieldtier.fileanalysis.uploadFiles(session.id);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <span className="text-[11px] text-[color:var(--st-text-muted)]">{counts.total} file{counts.total !== 1 ? 's' : ''}</span>
        {counts.critical > 0 && <Badge variant="destructive" size="sm">{counts.critical} critical</Badge>}
        {counts.high > 0 && <Badge variant="warning" size="sm">{counts.high} high risk</Badge>}
        {counts.analyzing > 0 && <Badge variant="default" size="sm">{counts.analyzing} analyzing</Badge>}
        <div className="flex-1" />
        <button type="button" onClick={handleUpload} className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] flex items-center gap-1.5 transition-colors cursor-pointer">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 9V3M6 3L3.5 5.5M6 3L8.5 5.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M2 10h8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
          </svg>
          Upload File
        </button>
      </div>

      {/* Main content: File list + Detail */}
      <div className="flex-1 flex overflow-hidden">
        {/* File List (left) */}
        <div className={cn('flex flex-col overflow-hidden', selectedFile ? 'w-2/5 border-r border-[color:var(--st-border)]' : 'w-full')}>
          <div className="flex-1 overflow-y-auto">
            {fileList.length === 0 ? (
              <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
                <div className="text-center">
                  <p className="mb-1">No files intercepted yet</p>
                  <p className="text-[10px] text-[color:var(--st-text-muted)]">Files downloaded in the sandboxed browser will appear here<br/>for automatic analysis</p>
                  <Button variant="outline" size="sm" onClick={handleUpload} className="mt-3 text-[10px]">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="mr-1.5">
                      <path d="M6 9V3M6 3L3.5 5.5M6 3L8.5 5.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M2 10h8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
                    </svg>
                    Upload File
                  </Button>
                </div>
              </div>
            ) : (
              fileList.map(file => {
                const rColors = RISK_COLORS[file.riskLevel] || RISK_COLORS.unknown;
                const isSelected = selectedFileId === file.id;
                const isProcessing = file.status !== 'complete' && file.status !== 'error';

                return (
                  <button
                    key={file.id}
                    onClick={() => setSelectedFileId(isSelected ? null : file.id)}
                    className={cn(
                      'flex items-center w-full px-3 py-2 text-left hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer',
                      isSelected ? 'bg-[color:var(--st-accent-dim)] border-l-2 border-l-[color:var(--st-accent)]' : 'border-l-2 border-l-transparent'
                    )}
                  >
                    <span className={cn('w-2.5 h-2.5 rounded-full shrink-0', rColors.dot, isProcessing && 'animate-pulse')} />
                    <div className="ml-2.5 min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[color:var(--st-text-primary)] truncate font-mono" title={file.originalName}>{file.originalName}</span>
                        <span className="text-[9px] text-[color:var(--st-text-muted)] shrink-0 font-mono">{formatFileSize(file.fileSize)}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant={riskBadgeVariant(file.riskLevel)} size="sm" className="capitalize">
                          {file.riskLevel}
                        </Badge>
                        {file.staticAnalysis && (
                          <span className="text-[10px] text-[color:var(--st-text-muted)]">{file.staticAnalysis.fileType}</span>
                        )}
                        {isProcessing && (
                          <span className="text-[10px] text-[color:var(--st-accent)]">{STATUS_LABELS[file.status]}</span>
                        )}
                        {file.staticAnalysis && file.staticAnalysis.findings.length > 0 && (
                          <span className="text-[10px] text-[color:var(--st-text-muted)]">{file.staticAnalysis.findings.length} finding{file.staticAnalysis.findings.length !== 1 ? 's' : ''}</span>
                        )}
                        {file.behavioralAnalysisRunning && (
                          <Badge variant="purple" size="sm" className="animate-pulse">Analyzing...</Badge>
                        )}
                        {file.behavioralAnalysisDone && !file.behavioralAnalysisRunning && (
                          <Badge variant="purple" size="sm">Behavioral</Badge>
                        )}
                        {!file.behavioralAnalysisDone && !file.behavioralAnalysisRunning && !file.archiveInfo?.isArchive && file.status === 'complete' && (
                          <span className="text-[10px] text-[color:var(--st-text-muted)]">No behavioral</span>
                        )}
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Detail panel (right) */}
        {selectedFile && (
          <div className="w-3/5 overflow-y-auto p-4">
            <FileDetail
              file={selectedFile}
              sessionId={session.id}
              onClose={() => setSelectedFileId(null)}
              onDelete={() => handleDelete(selectedFile.id)}
              onResubmit={() => handleResubmit(selectedFile.id)}
              onAnalyzeBehavior={() => handleAnalyzeBehavior(selectedFile.id)}
            />
          </div>
        )}
      </div>

    </div>
  );
}

// ═══════════════════════════════════════════════════════
// EnrichmentCard
// ═══════════════════════════════════════════════════════

function EnrichmentCard({ result: er }: { result: EnrichmentResult }) {
  const [expanded, setExpanded] = useState(false);
  const vColors = VERDICT_COLORS[er.verdict] || VERDICT_COLORS.unknown;

  return (
    <Card className={cn('p-0 overflow-hidden', vColors.bg)}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-3 py-2.5 text-left"
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className={cn('w-2 h-2 rounded-full shrink-0', vColors.dot)} />
          <span className="text-[color:var(--st-text-primary)] font-medium truncate" title={PROVIDER_LABELS[er.provider] || er.provider}>{PROVIDER_LABELS[er.provider] || er.provider}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge
            variant={er.verdict === 'malicious' ? 'destructive' : er.verdict === 'suspicious' ? 'warning' : er.verdict === 'clean' ? 'success' : 'outline'}
            size="sm"
            className="capitalize"
          >
            {er.verdict}
          </Badge>
          {er.confidence > 0 && (
            <div className="flex items-center gap-1">
              <div className="w-12 h-1.5 bg-[color:var(--st-bg-panel)] rounded-full overflow-hidden">
                <div className={cn('h-full rounded-full', vColors.dot)} style={{ width: `${er.confidence}%` }} />
              </div>
              <span className="text-[9px] text-[color:var(--st-text-muted)] font-mono">{er.confidence}%</span>
            </div>
          )}
          <svg width="10" height="10" viewBox="0 0 10 10" className={cn('text-[color:var(--st-text-muted)] transition-transform', expanded && 'rotate-180')}>
            <path d="M2 4L5 7L8 4" stroke="currentColor" strokeWidth="1.5" fill="none" />
          </svg>
        </div>
      </button>
      {expanded && (
        <CardContent className="px-3 pb-3 space-y-2 border-t border-[color:var(--st-border)]">
          {er.summary && (
            <p className="text-[color:var(--st-text-secondary)] text-[11px] pt-2">{er.summary}</p>
          )}
          {er.error && (
            <p className="text-[color:var(--st-danger)] text-[10px] pt-1">{er.error}</p>
          )}
          {Object.keys(er.details).length > 0 && (
            <div className="space-y-1.5 pt-1">
              {Object.entries(er.details).map(([key, value]) => {
                if (value === null || value === undefined) return null;
                return <DetailValue key={key} label={key} value={value} />;
              })}
            </div>
          )}
          <p className="text-[9px] text-[color:var(--st-text-muted)] pt-1 font-mono">
            {new Date(er.timestamp).toLocaleString()}
          </p>
        </CardContent>
      )}
    </Card>
  );
}

// ═══════════════════════════════════════════════════════
// DetailValue (reused locally for enrichment card expansion)
// ═══════════════════════════════════════════════════════

function DetailValue({ label, value }: { label: string; value: any }) {
  const [expanded, setExpanded] = useState(false);

  if (typeof value !== 'object') {
    const str = String(value);
    if (str.length > 200 && !expanded) {
      return (
        <div className="flex items-start gap-2">
          <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
          <div className="flex-1 min-w-0">
            <span className="text-[color:var(--st-text-muted)] break-all">{str.slice(0, 200)}...</span>
            <Button variant="link" size="sm" onClick={() => setExpanded(true)} className="ml-1 h-auto p-0 text-[10px]">Show more</Button>
          </div>
        </div>
      );
    }
    return (
      <div className="flex items-start gap-2">
        <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
        <span className="text-[color:var(--st-text-muted)] break-all">{str}</span>
        {expanded && <Button variant="link" size="sm" onClick={() => setExpanded(false)} className="ml-1 h-auto p-0 text-[10px] shrink-0">Less</Button>}
      </div>
    );
  }

  if (Array.isArray(value) && value.length > 0 && value.every(v => typeof v === 'string' || typeof v === 'number')) {
    return (
      <div className="flex items-start gap-2">
        <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
        <div className="flex flex-wrap gap-1">
          {value.map((v, i) => (
            <Badge key={i} variant="outline" size="sm">{String(v)}</Badge>
          ))}
        </div>
      </div>
    );
  }

  if (Array.isArray(value) && value.length === 0) {
    return (
      <div className="flex items-start gap-2">
        <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
        <span className="text-[color:var(--st-text-muted)] italic">None</span>
      </div>
    );
  }

  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).filter(([, v]) => v !== null && v !== undefined);
    if (entries.length === 0) return null;
    return (
      <div>
        <span className="text-[color:var(--st-text-muted)] text-[10px]">{label}</span>
        <div className="ml-3 mt-0.5 space-y-0.5 border-l border-[color:var(--st-border)] pl-2">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2">
              <span className="text-[color:var(--st-text-muted)] text-[10px] w-16 shrink-0">{k}</span>
              <span className="text-[color:var(--st-text-muted)] text-[10px] break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return null;
}

// ═══════════════════════════════════════════════════════
// ArchivePasswordPrompt
// ═══════════════════════════════════════════════════════

function ArchivePasswordPrompt({ file, sessionId }: { file: QuarantinedFile; sessionId: string }) {
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim()) return;
    setSubmitting(true);
    await window.shieldtier.fileanalysis.submitArchivePassword(sessionId, file.id, password);
    setPassword('');
    setSubmitting(false);
  };

  const handleSkip = async () => {
    await window.shieldtier.fileanalysis.skipArchivePassword(sessionId, file.id);
  };

  const typeLabel = file.archiveInfo?.archiveType === 'pdf' ? 'PDF'
    : file.archiveInfo?.archiveType === 'office' ? 'Office document'
    : file.archiveInfo?.archiveType === 'zip' ? 'ZIP archive'
    : file.archiveInfo?.archiveType === 'rar' ? 'RAR archive'
    : file.archiveInfo?.archiveType === '7z' ? '7z archive'
    : 'file';

  return (
    <Card className="p-0 border-[color:var(--st-warning)]/30 bg-[color:var(--st-warning-dim)] mb-3">
      <CardContent className="px-3 py-3">
        <div className="flex items-center gap-2 mb-2">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
            <rect x="3" y="6" width="8" height="6" rx="1" stroke="#eab308" strokeWidth="1.2" />
            <path d="M5 6V4a2 2 0 0 1 4 0v2" stroke="#eab308" strokeWidth="1.2" strokeLinecap="round" />
          </svg>
          <span className="text-xs text-[color:var(--st-warning)] font-medium">Password-protected {typeLabel}</span>
        </div>
        {file.archiveInfo?.passwordError && (
          <p className="text-[10px] text-[color:var(--st-danger)] mb-2">{file.archiveInfo.passwordError}</p>
        )}
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <Input
            ref={inputRef}
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Enter password..."
            disabled={submitting}
            className="flex-1 h-7 text-xs"
          />
          <Button
            type="submit"
            disabled={submitting || !password.trim()}
            variant="outline"
            size="sm"
            className="bg-[color:var(--st-warning-dim)] text-[color:var(--st-warning)] border-[color:var(--st-warning)]/30 hover:brightness-110"
          >
            {submitting ? 'Unlocking...' : 'Unlock'}
          </Button>
          <Button
            type="button"
            onClick={handleSkip}
            variant="outline"
            size="sm"
          >
            Skip
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════
// FileDetail
// ═══════════════════════════════════════════════════════

function FileDetail({ file, sessionId, onClose, onDelete, onResubmit, onAnalyzeBehavior }: {
  file: QuarantinedFile;
  sessionId: string;
  onClose: () => void;
  onDelete: () => void;
  onResubmit: () => void;
  onAnalyzeBehavior: () => void;
}) {
  const [tab, setTab] = useState<'overview' | 'static' | 'sandbox' | 'enrichment' | 'mitre'>('overview');
  const rColors = RISK_COLORS[file.riskLevel] || RISK_COLORS.unknown;

  // Enrichment results for this file's SHA256
  const [enrichmentResults, setEnrichmentResults] = useState<EnrichmentResult[]>([]);
  useEffect(() => {
    if (!file.hashEnrichmentDone || !file.hashes?.sha256) return;
    (async () => {
      try {
        const allEntries = await window.shieldtier.enrichment.getResults(sessionId);
        const entry = allEntries.find(e => e.value === file.hashes!.sha256);
        if (entry && entry.results.length > 0) {
          setEnrichmentResults(entry.results);
        }
      } catch {}
    })();
  }, [sessionId, file.hashEnrichmentDone, file.hashes?.sha256]);

  // Compute MITRE count for tab label
  const mitreCount = (() => {
    const ids = new Set<string>();
    if (file.staticAnalysis?.findings) {
      for (const f of file.staticAnalysis.findings) { if (f.mitre) ids.add(f.mitre); }
    }
    for (const sr of file.sandboxResults) {
      if (sr.details?.signatures) { for (const s of sr.details.signatures as any[]) { if (s.mitre) ids.add(s.mitre); } }
      if (sr.details?.advancedFindings) { for (const af of sr.details.advancedFindings as any[]) { if (af.mitre) ids.add(af.mitre); } }
    }
    return ids.size;
  })();

  return (
    <div className="text-xs">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={cn('w-2.5 h-2.5 rounded-full', rColors.dot)} />
            <span className="text-sm text-[color:var(--st-text-primary)] font-medium break-all font-mono" title={file.originalName}>{file.originalName}</span>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-[color:var(--st-text-muted)] ml-4">
            <span className="font-mono">{formatFileSize(file.fileSize)}</span>
            {file.staticAnalysis && <span>{file.staticAnalysis.fileType}</span>}
            <span className="font-mono">{new Date(file.createdAt).toLocaleTimeString()}</span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          {!file.behavioralAnalysisDone && !file.archiveInfo?.isArchive && file.status === 'complete' && (
            <button
              type="button"
              onClick={onAnalyzeBehavior}
              className="h-7 px-2 rounded-md text-[10px] font-medium text-[color:var(--st-purple)] hover:bg-[color:var(--st-purple-dim)] transition-colors cursor-pointer"
              title="Run behavioral analysis (PE Capability, Script Detonation, Shellcode Emulation)"
            >
              Analyze Behavior
            </button>
          )}
          {file.behavioralAnalysisDone && (
            <button
              type="button"
              onClick={onResubmit}
              className="h-7 px-2 rounded-md text-[10px] font-medium text-[color:var(--st-accent)] hover:bg-[color:var(--st-accent-dim)] transition-colors cursor-pointer"
              title="Re-run behavioral analysis"
            >
              Re-analyze
            </button>
          )}
          <button
            type="button"
            onClick={onDelete}
            className="h-7 px-2 rounded-md text-[10px] font-medium text-[color:var(--st-danger)] hover:bg-[color:var(--st-danger-dim)] transition-colors cursor-pointer"
            title="Delete quarantined file"
          >
            Delete
          </button>
          <button type="button" onClick={onClose} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] cursor-pointer">
            <svg width="10" height="10" viewBox="0 0 12 12"><path d="M3 3L9 9M9 3L3 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
          </button>
        </div>
      </div>

      {/* Risk level badge */}
      <div className={cn('rounded-lg px-3 py-2 mb-3', rColors.bg)}>
        <Badge variant={riskBadgeVariant(file.riskLevel)} className="capitalize">
          Risk: {file.riskLevel}
        </Badge>
        {file.status !== 'complete' && file.status !== 'error' && (
          <span className="ml-2 text-[10px] text-[color:var(--st-accent)]">{STATUS_LABELS[file.status]}</span>
        )}
        {file.error && (
          <span className="ml-2 text-[10px] text-[color:var(--st-danger)]">{file.error}</span>
        )}
      </div>

      {/* Archive password prompt */}
      {file.status === 'password-required' && (
        <ArchivePasswordPrompt
          file={file}
          sessionId={sessionId}
        />
      )}

      {/* Child files (extracted from archive) */}
      {file.childFileIds && file.childFileIds.length > 0 && (
        <Card className="p-0 mb-3 bg-[color:var(--st-bg-panel)]">
          <CardContent className="px-3 py-2">
            <p className="text-[10px] text-[color:var(--st-text-muted)] mb-1">Extracted Files ({file.childFileIds.length})</p>
            <div className="flex flex-wrap gap-1">
              {file.childFileIds.map(cid => (
                <Badge key={cid} variant="default" size="sm" className="font-mono">{cid.slice(0, 8)}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Parent archive link */}
      {file.parentArchiveId && (
        <Card className="p-0 mb-3 bg-[color:var(--st-bg-panel)]">
          <CardContent className="px-2 py-1.5">
            <p className="text-[10px] text-[color:var(--st-text-muted)]">
              Extracted from archive <span className="text-[color:var(--st-accent)] font-mono">{file.parentArchiveId.slice(0, 8)}</span>
            </p>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="w-full">
        <TabsList className="mb-3">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="static">Static ({file.staticAnalysis?.findings.length || 0})</TabsTrigger>
          <TabsTrigger value="sandbox">Behavioral ({file.sandboxResults.length})</TabsTrigger>
          <TabsTrigger value="enrichment">Investigation ({enrichmentResults.length})</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ({mitreCount})</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview">
          <div className="space-y-3">
            {/* Hashes */}
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Hashes</p>
              <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1 font-mono">
                {file.hashes ? (
                  <>
                    <p className="text-[color:var(--st-text-secondary)] break-all" title={file.hashes.md5}><span className="text-[color:var(--st-text-muted)]">MD5: </span>{file.hashes.md5}</p>
                    <p className="text-[color:var(--st-text-secondary)] break-all" title={file.hashes.sha1}><span className="text-[color:var(--st-text-muted)]">SHA1: </span>{file.hashes.sha1}</p>
                    <p className="text-[color:var(--st-text-secondary)] break-all" title={file.hashes.sha256}><span className="text-[color:var(--st-text-muted)]">SHA256: </span>{file.hashes.sha256}</p>
                  </>
                ) : (
                  <p className="text-[color:var(--st-text-muted)]">Computing...</p>
                )}
              </div>
            </div>

            {/* File Info */}
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">File Information</p>
              <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1">
                <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Name: </span><span className="font-mono">{file.originalName}</span></p>
                <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Size: </span><span className="font-mono">{formatFileSize(file.fileSize)}</span></p>
                <p className="text-[color:var(--st-text-secondary)] break-all"><span className="text-[color:var(--st-text-muted)]">Source URL: </span><span className="font-mono">{file.url}</span></p>
                {file.staticAnalysis && (
                  <>
                    <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Type: </span>{file.staticAnalysis.fileType}</p>
                    <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">MIME: </span><span className="font-mono">{file.staticAnalysis.mimeType}</span></p>
                    <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Entropy: </span><span className="font-mono">{file.staticAnalysis.entropy.toFixed(2)}/8.0</span></p>
                  </>
                )}
              </div>
            </div>

            {/* Quick findings summary */}
            {file.staticAnalysis && file.staticAnalysis.findings.length > 0 && (
              <div>
                <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Key Findings</p>
                <div className="space-y-1">
                  {file.staticAnalysis.findings.slice(0, 5).map((f, i) => {
                    const fColors = RISK_COLORS[f.severity] || RISK_COLORS.unknown;
                    return (
                      <div key={i} className={cn('flex items-start gap-2 px-2 py-1.5 rounded', fColors.bg)}>
                        <span className={cn('w-1.5 h-1.5 rounded-full mt-1 shrink-0', fColors.dot)} />
                        <div>
                          <Badge variant={riskBadgeVariant(f.severity)} size="sm" className="uppercase">
                            {f.severity}
                          </Badge>
                          <p className="text-[color:var(--st-text-secondary)] text-[11px]">{f.description}</p>
                        </div>
                      </div>
                    );
                  })}
                  {file.staticAnalysis.findings.length > 5 && (
                    <p className="text-[10px] text-[color:var(--st-text-muted)] ml-4">+{file.staticAnalysis.findings.length - 5} more findings (see Static tab)</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Static Tab */}
        <TabsContent value="static">
          <div className="space-y-3">
            {!file.staticAnalysis ? (
              <p className="text-[color:var(--st-text-muted)] text-center py-4">
                {file.status === 'complete' ? 'No static analysis data' : 'Analysis in progress...'}
              </p>
            ) : (
              <>
                {/* Entropy */}
                <div>
                  <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Entropy</p>
                  <div className="bg-[color:var(--st-bg-base)] rounded p-2">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-[color:var(--st-bg-panel)] rounded-full overflow-hidden">
                        <div
                          className={cn(
                            'h-full rounded-full',
                            file.staticAnalysis.entropy > 7 ? 'bg-[color:var(--st-danger)]' : file.staticAnalysis.entropy > 5 ? 'bg-[color:var(--st-warning)]' : 'bg-[color:var(--st-success)]'
                          )}
                          style={{ width: `${(file.staticAnalysis.entropy / 8) * 100}%` }}
                        />
                      </div>
                      <span className="text-[color:var(--st-text-secondary)] w-12 text-right font-mono">{file.staticAnalysis.entropy.toFixed(2)}/8</span>
                    </div>
                  </div>
                </div>

                {/* All Findings */}
                <div>
                  <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Findings ({file.staticAnalysis.findings.length})</p>
                  {file.staticAnalysis.findings.length === 0 ? (
                    <p className="text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-base)] rounded p-2">No suspicious findings</p>
                  ) : (
                    <div className="space-y-1">
                      {file.staticAnalysis.findings.map((f, i) => {
                        const fColors = RISK_COLORS[f.severity] || RISK_COLORS.unknown;
                        return (
                          <div key={i} className={cn('flex items-start gap-2 px-2 py-1.5 rounded', fColors.bg)}>
                            <span className={cn('w-1.5 h-1.5 rounded-full mt-1 shrink-0', fColors.dot)} />
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <Badge variant={riskBadgeVariant(f.severity)} size="sm" className="uppercase shrink-0">
                                  {f.severity}
                                </Badge>
                                <span className="text-[9px] text-[color:var(--st-text-muted)] shrink-0">{f.category}</span>
                              </div>
                              <p className="text-[color:var(--st-text-secondary)] text-[11px]">{f.description}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Metadata */}
                {Object.keys(file.staticAnalysis.metadata).length > 0 && (
                  <div>
                    <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Metadata</p>
                    <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1">
                      {Object.entries(file.staticAnalysis.metadata).map(([key, value]) => {
                        if (value === null || value === undefined) return null;
                        const displayValue = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
                        return (
                          <div key={key} className="flex items-start gap-2">
                            <span className="text-[color:var(--st-text-muted)] w-24 shrink-0">{key}</span>
                            <span className="text-[color:var(--st-text-muted)] break-all">{displayValue.length > 200 ? displayValue.slice(0, 200) + '...' : displayValue}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Suspicious Strings */}
                {file.staticAnalysis.strings && file.staticAnalysis.strings.length > 0 && (
                  <div>
                    <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Suspicious Strings ({file.staticAnalysis.strings.length})</p>
                    <div className="bg-[color:var(--st-bg-base)] rounded p-2 max-h-40 overflow-y-auto">
                      {file.staticAnalysis.strings.map((s, i) => (
                        <p key={i} className="text-[color:var(--st-text-muted)] font-mono text-[10px] break-all">{s}</p>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </TabsContent>

        {/* Sandbox (Behavioral) Tab */}
        <TabsContent value="sandbox">
          <div className="text-center py-8">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-3 text-[color:var(--st-text-muted)]">
              <path d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5z"/><line x1="16" y1="8" x2="2" y2="22"/><line x1="17.5" y1="15" x2="9" y2="15"/>
            </svg>
            <p className="text-[color:var(--st-text-muted)] text-sm mb-1">Behavioral analysis has moved to the Sandbox panel</p>
            <p className="text-[color:var(--st-text-muted)] text-xs">Use the Behavioral Sandbox tab in the left sidebar to view full analysis details.</p>
            {!file.behavioralAnalysisDone && !file.behavioralAnalysisRunning && file.status === 'complete' && !file.archiveInfo?.isArchive && (
              <button
                type="button"
                onClick={onAnalyzeBehavior}
                className="mt-3 h-7 px-2.5 rounded-md text-[11px] font-medium bg-[color:var(--st-purple)] text-white hover:brightness-110 transition-colors cursor-pointer"
              >
                Analyze Behavior
              </button>
            )}
            {file.behavioralAnalysisRunning && (
              <div className="mt-3">
                <div className="inline-block w-5 h-5 border-2 border-[color:var(--st-purple)] border-t-transparent rounded-full animate-spin mb-2" />
                <p className="text-[color:var(--st-purple)] text-xs animate-pulse">Running behavioral analysis...</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Enrichment (Investigation) Tab */}
        <TabsContent value="enrichment">
          <div className="space-y-3">
            {enrichmentResults.length === 0 ? (
              <p className="text-[color:var(--st-text-muted)] text-center py-4">
                {!file.hashEnrichmentDone ? 'Hash investigation in progress...' : 'No investigation results for this file hash'}
              </p>
            ) : (
              enrichmentResults.map((er, i) => (
                <EnrichmentCard key={`${er.provider}-${i}`} result={er} />
              ))
            )}
          </div>
        </TabsContent>

        {/* MITRE Tab */}
        <TabsContent value="mitre">
          <MITREMappingTab files={[file]} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
