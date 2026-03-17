import React, { useState, useEffect, useMemo } from 'react';
import type { InvestigationSession } from '../shared/types';
import type { QuarantinedFile, AnalysisFinding } from '../types';
import MITREMappingTab from './MITREMappingTab';
import type { MITREEvidence, MITRELogEvent } from './MITREMappingTab';

// ---------------------------------------------------------------------------
// Log analysis types (mirrored from main — renderer cannot import directly)
// ---------------------------------------------------------------------------

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface VerdictSignal {
  title: string;
  severity: Severity;
  evidence: string;
  mitre?: string;
}

interface LogVerdict {
  verdict: string;
  confidence: number;
  signals: VerdictSignal[];
  falsePositives: string[];
  killChain: string[];
  reasoning: string;
}

interface HuntingQuery {
  id: string;
  name: string;
  description: string;
  mitre: string;
  category: string;
  severity: Severity;
  source: string;
}

interface HuntingMatch {
  event: any;
  evidence: string;
}

interface HuntingQueryResult {
  query: HuntingQuery;
  matches: HuntingMatch[];
  matchCount: number;
}

interface LogAnalysisResult {
  id: string;
  fileName: string;
  verdict: LogVerdict | null;
  hunting: HuntingQueryResult[] | null;
  status: string;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface MITREPanelProps {
  session: InvestigationSession;
  files: Map<string, QuarantinedFile>;
}

// ---------------------------------------------------------------------------
// Severity mapping (log analysis Severity → AnalysisFinding FileRiskLevel)
// ---------------------------------------------------------------------------

function mapSeverity(sev: Severity): AnalysisFinding['severity'] {
  return sev as AnalysisFinding['severity'];
}

// ---------------------------------------------------------------------------
// Build MITRE evidence from log analysis results
// ---------------------------------------------------------------------------

function buildLogAnalysisEvidence(results: LogAnalysisResult[]): Map<string, MITREEvidence[]> {
  const byTechnique = new Map<string, MITREEvidence[]>();

  for (const result of results) {
    if (result.status !== 'complete') continue;
    const source = result.fileName;

    // Verdict signals → MITRE evidence (with event details)
    if (result.verdict?.signals) {
      // Group signals by MITRE ID so we get one evidence entry per technique
      const byMitre = new Map<string, VerdictSignal[]>();
      for (const sig of result.verdict.signals) {
        if (!sig.mitre) continue;
        const list = byMitre.get(sig.mitre) || [];
        list.push(sig);
        byMitre.set(sig.mitre, list);
      }
      for (const [mitreId, sigs] of byMitre) {
        // Use the highest severity from all signals for this technique
        const maxSev = sigs.reduce((max, s) => {
          const order: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
          return (order[s.severity] || 0) > (order[max] || 0) ? s.severity : max;
        }, 'info' as Severity);

        const finding: AnalysisFinding = {
          severity: mapSeverity(maxSev),
          category: 'verdict',
          description: `${sigs[0].title} (${sigs.length} signal${sigs.length !== 1 ? 's' : ''})`,
          mitre: mitreId,
        };
        // Attach actual signal evidence as log events
        const logEvents: MITRELogEvent[] = sigs.map(s => ({
          timestamp: '',
          eventType: s.title,
          evidence: s.evidence,
        }));
        const list = byTechnique.get(mitreId) || [];
        list.push({ finding, source, sourceType: 'log-verdict', logEvents });
        byTechnique.set(mitreId, list);
      }
    }

    // Hunting query matches → MITRE evidence (with matched events)
    if (result.hunting) {
      for (const hq of result.hunting) {
        const mitreId = hq.query.mitre;
        if (!mitreId) continue;
        const finding: AnalysisFinding = {
          severity: mapSeverity(hq.query.severity),
          category: 'hunting',
          description: `${hq.query.name} (${hq.matchCount} match${hq.matchCount !== 1 ? 'es' : ''})`,
          mitre: mitreId,
        };
        // Attach actual matched events
        const logEvents: MITRELogEvent[] = hq.matches.map(m => ({
          timestamp: m.event.timestamp || '',
          eventType: m.event.eventType || '',
          evidence: m.evidence,
        }));
        const list = byTechnique.get(mitreId) || [];
        list.push({ finding, source, sourceType: 'log-hunting', logEvents });
        byTechnique.set(mitreId, list);
      }
    }
  }

  return byTechnique;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function MITREPanel({ session, files }: MITREPanelProps) {
  const allFiles = useMemo(() => Array.from(files.values()), [files]);

  // Load log analysis results
  const [logResults, setLogResults] = useState<LogAnalysisResult[]>([]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const results = await window.shieldtier.loganalysis.getResults(session.id);
        if (!cancelled) setLogResults(results || []);
      } catch {
        // Log analysis may not be available
      }
    }
    load();

    // Listen for new completions
    const unsub = window.shieldtier.loganalysis.onComplete((sessionId: string) => {
      if (sessionId === session.id) load();
    });

    return () => { cancelled = true; unsub(); };
  }, [session.id]);

  // Build extra MITRE evidence from log analysis
  const logEvidence = useMemo(() => buildLogAnalysisEvidence(logResults), [logResults]);

  // Count sources
  const filesWithFindings = useMemo(() =>
    allFiles.filter(f =>
      f.staticAnalysis?.findings?.some(fin => fin.mitre) ||
      f.sandboxResults?.some(sr =>
        (sr.details?.signatures as any[])?.some((s: any) => s.mitre) ||
        (sr.details?.advancedFindings as any[])?.some((af: any) => af.mitre)
      )
    ),
    [allFiles]
  );

  const logFilesWithMitre = logResults.filter(r =>
    r.status === 'complete' && (
      r.verdict?.signals?.some(s => s.mitre) ||
      r.hunting?.some(h => h.query.mitre)
    )
  );

  const hasAnyData = allFiles.length > 0 || logResults.length > 0;
  const hasAnyMitre = filesWithFindings.length > 0 || logEvidence.size > 0;

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="max-w-6xl mx-auto space-y-4">
        {/* Header */}
        <div>
          <h2 className="text-sm font-medium text-[color:var(--st-text-primary)]" aria-label="MITRE ATT&CK Investigation Overview">MITRE ATT&CK — Investigation Overview</h2>
          <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">
            {allFiles.length > 0 && (
              <span>{allFiles.length} file{allFiles.length !== 1 ? 's' : ''} analyzed</span>
            )}
            {allFiles.length > 0 && logResults.length > 0 && <span> · </span>}
            {logResults.length > 0 && (
              <span>{logResults.length} log{logResults.length !== 1 ? 's' : ''} analyzed</span>
            )}
            {filesWithFindings.length > 0 && ` · ${filesWithFindings.length} file${filesWithFindings.length !== 1 ? 's' : ''} with MITRE`}
            {logFilesWithMitre.length > 0 && ` · ${logFilesWithMitre.length} log${logFilesWithMitre.length !== 1 ? 's' : ''} with MITRE`}
            {logEvidence.size > 0 && ` · ${logEvidence.size} technique${logEvidence.size !== 1 ? 's' : ''} from logs`}
          </p>
        </div>

        {!hasAnyData ? (
          <div className="flex flex-col items-center justify-center py-16 text-[color:var(--st-text-muted)] text-xs gap-2">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="text-[color:var(--st-text-muted)] mb-1"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <span>No analysis data yet</span>
            <span className="text-[color:var(--st-text-muted)] text-[10px] max-w-sm text-center">
              MITRE ATT&CK mappings appear automatically when files are analyzed in the Sandbox panel
              or logs are processed in the Log Analysis panel. Download a file or open a log to get started.
            </span>
          </div>
        ) : !hasAnyMitre ? (
          <div className="flex flex-col items-center justify-center py-16 text-[color:var(--st-text-muted)] text-xs gap-2">
            <span>No MITRE ATT&CK techniques identified in current analysis results</span>
            <span className="text-[color:var(--st-text-muted)] text-[10px] max-w-sm text-center">
              Techniques are mapped when behavioral findings, YARA rule matches, or hunting queries
              contain MITRE references. Try analyzing a more complex sample or log file.
            </span>
          </div>
        ) : (
          <MITREMappingTab
            files={allFiles}
            showSources={true}
            extraEvidence={logEvidence}
          />
        )}
      </div>
    </div>
  );
}
