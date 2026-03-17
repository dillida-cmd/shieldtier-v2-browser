import React, { useState, useMemo } from 'react';
import type { QuarantinedFile, AnalysisFinding, FileRiskLevel } from '../types';
import { lookupMITRE, TACTIC_ORDER, TACTIC_DISPLAY_NAMES, TACTIC_COLORS } from '../shared/mitre-attack-db';
import type { MITRETactic, MITRETechnique } from '../shared/mitre-attack-db';

// ═══════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════

/** A single matched log event (for log-verdict / log-hunting evidence). */
interface MITRELogEvent {
  timestamp: string;
  eventType: string;
  evidence: string;
}

interface MITREEvidence {
  finding: AnalysisFinding;
  source: string; // file name or 'web-sandbox'
  sourceType: string; // 'static' | 'sandbox-signature' | 'advanced' | 'yara' | 'log-verdict' | 'log-hunting'
  /** Actual log events that triggered this detection (log analysis only). */
  logEvents?: MITRELogEvent[];
}

interface TechniqueGroup {
  technique: MITRETechnique;
  id: string;
  evidenceItems: MITREEvidence[];
  maxSeverity: FileRiskLevel;
}

interface TacticColumn {
  tactic: MITRETactic;
  techniques: TechniqueGroup[];
}

// ═══════════════════════════════════════════════════════
// Props
// ═══════════════════════════════════════════════════════

interface MITREMappingTabProps {
  files: QuarantinedFile[];
  /** If true, show source file attribution on each evidence item */
  showSources?: boolean;
  /** Additional pre-aggregated MITRE evidence from external sources (log analysis, etc.) */
  extraEvidence?: Map<string, MITREEvidence[]>;
}

/** Re-export for external aggregation */
export type { MITREEvidence, MITRELogEvent };

// ═══════════════════════════════════════════════════════
// Severity helpers
// ═══════════════════════════════════════════════════════

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0,
};

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-600/20', text: 'text-red-400', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-600/20', text: 'text-orange-400', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-600/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-blue-600/20', text: 'text-blue-400', border: 'border-blue-500/30' },
  info: { bg: 'bg-gray-600/20', text: 'text-gray-400', border: 'border-gray-500/30' },
};

function maxSeverity(items: MITREEvidence[]): FileRiskLevel {
  let max: FileRiskLevel = 'info';
  for (const item of items) {
    if ((SEVERITY_ORDER[item.finding.severity] || 0) > (SEVERITY_ORDER[max] || 0)) {
      max = item.finding.severity;
    }
  }
  return max;
}

// ═══════════════════════════════════════════════════════
// Aggregation
// ═══════════════════════════════════════════════════════

function aggregateMITRE(files: QuarantinedFile[]): Map<string, MITREEvidence[]> {
  const byTechnique = new Map<string, MITREEvidence[]>();

  for (const file of files) {
    const fileName = file.originalName;

    // Static analysis findings
    if (file.staticAnalysis?.findings) {
      for (const finding of file.staticAnalysis.findings) {
        if (finding.mitre) {
          const list = byTechnique.get(finding.mitre) || [];
          list.push({ finding, source: fileName, sourceType: 'static' });
          byTechnique.set(finding.mitre, list);
        }
      }
    }

    // Sandbox results — signatures + advanced findings
    for (const sr of file.sandboxResults) {
      if (sr.details?.signatures) {
        for (const sig of sr.details.signatures as any[]) {
          if (sig.mitre) {
            const evidenceDescs = (sig.evidence as string[]) || [];
            const finding: AnalysisFinding = {
              severity: sig.severity || 'medium',
              category: sig.name || 'behavioral',
              description: evidenceDescs[0] || sig.name || '',
              mitre: sig.mitre,
            };
            const list = byTechnique.get(sig.mitre) || [];
            list.push({ finding, source: sr.provider === 'inline' ? 'web-sandbox' : fileName, sourceType: 'sandbox-signature' });
            byTechnique.set(sig.mitre, list);
          }
        }
      }

      if (sr.details?.advancedFindings) {
        for (const af of sr.details.advancedFindings as any[]) {
          if (af.mitre) {
            const finding: AnalysisFinding = {
              severity: af.severity || 'medium',
              category: af.category || 'advanced',
              description: af.description || '',
              mitre: af.mitre,
            };
            const list = byTechnique.get(af.mitre) || [];
            list.push({ finding, source: af.source || fileName, sourceType: 'advanced' });
            byTechnique.set(af.mitre, list);
          }
        }
      }
    }
  }

  return byTechnique;
}

function buildTacticColumns(byTechnique: Map<string, MITREEvidence[]>): TacticColumn[] {
  // Group techniques by tactic
  const tacticMap = new Map<MITRETactic, TechniqueGroup[]>();

  for (const [id, evidence] of byTechnique) {
    const technique = lookupMITRE(id);
    if (!technique) continue;

    const group: TechniqueGroup = {
      technique,
      id,
      evidenceItems: evidence,
      maxSeverity: maxSeverity(evidence),
    };

    // Place under primary tactic
    const tactic = technique.tactic;
    const list = tacticMap.get(tactic) || [];
    list.push(group);
    tacticMap.set(tactic, list);
  }

  // Sort techniques within each tactic by severity (highest first)
  for (const [, techniques] of tacticMap) {
    techniques.sort((a, b) => (SEVERITY_ORDER[b.maxSeverity] || 0) - (SEVERITY_ORDER[a.maxSeverity] || 0));
  }

  // Build columns in tactic order
  const columns: TacticColumn[] = [];
  for (const tactic of TACTIC_ORDER) {
    const techniques = tacticMap.get(tactic);
    if (techniques && techniques.length > 0) {
      columns.push({ tactic, techniques });
    }
  }

  return columns;
}

// ═══════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════

export default function MITREMappingTab({ files, showSources = false, extraEvidence }: MITREMappingTabProps) {
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);

  // Merge file-analysis evidence with extra evidence from log analysis, etc.
  const byTechnique = useMemo(() => {
    const fileEvidence = aggregateMITRE(files);
    if (!extraEvidence || extraEvidence.size === 0) return fileEvidence;
    // Merge extra evidence into file evidence map
    const merged = new Map(fileEvidence);
    for (const [techId, items] of extraEvidence) {
      const existing = merged.get(techId) || [];
      merged.set(techId, [...existing, ...items]);
    }
    return merged;
  }, [files, extraEvidence]);
  const columns = useMemo(() => buildTacticColumns(byTechnique), [byTechnique]);

  const totalTechniques = byTechnique.size;
  const totalTactics = columns.length;

  if (totalTechniques === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-[color:var(--st-text-muted)] text-xs">
        No MITRE ATT&CK techniques identified
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-[color:var(--st-text-primary)]">MITRE ATT&CK Coverage</span>
        </div>
        <span className="text-[10px] text-[color:var(--st-text-muted)]">
          {totalTechniques} technique{totalTechniques !== 1 ? 's' : ''} · {totalTactics} tactic{totalTactics !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Tactic columns */}
      <div className="bg-[color:var(--st-bg-base)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
        <div className="flex overflow-x-auto" style={{ minHeight: '120px' }}>
          {columns.map(col => (
            <div key={col.tactic} className="flex-1 min-w-[140px] border-r border-[color:var(--st-border)] last:border-r-0">
              {/* Tactic header */}
              <div
                className="px-2 py-1.5 text-[10px] font-medium border-b border-[color:var(--st-border)] text-center"
                style={{ borderTopWidth: '2px', borderTopStyle: 'solid', borderTopColor: TACTIC_COLORS[col.tactic] }}
              >
                <span style={{ color: TACTIC_COLORS[col.tactic] }}>
                  {TACTIC_DISPLAY_NAMES[col.tactic]}
                </span>
              </div>

              {/* Technique cards */}
              <div className="p-1.5 space-y-1">
                {col.techniques.map(group => {
                  const sev = SEVERITY_COLORS[group.maxSeverity] || SEVERITY_COLORS.info;
                  const isExpanded = expandedTechnique === group.id;
                  return (
                    <button
                      key={group.id}
                      onClick={() => setExpandedTechnique(isExpanded ? null : group.id)}
                      className={`w-full text-left rounded px-1.5 py-1 ${sev.bg} border ${sev.border} hover:brightness-110 transition-all`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-mono ${sev.text}`}>{group.id}</span>
                        <span className={`text-[9px] ${sev.bg} ${sev.text} px-1 rounded-full`}>
                          {group.evidenceItems.length}
                        </span>
                      </div>
                      <div className="text-[9px] text-[color:var(--st-text-muted)] truncate">{group.technique.name}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Expanded technique detail */}
      {expandedTechnique && byTechnique.has(expandedTechnique) && (() => {
        const technique = lookupMITRE(expandedTechnique);
        const evidence = byTechnique.get(expandedTechnique)!;
        const sev = SEVERITY_COLORS[maxSeverity(evidence)] || SEVERITY_COLORS.info;

        return (
          <div className={`bg-[color:var(--st-bg-base)] rounded-lg border ${sev.border} overflow-hidden`}>
            {/* Technique header */}
            <div className="flex items-center justify-between px-3 py-2 border-b border-[color:var(--st-border)]">
              <div className="flex items-center gap-2">
                <span className={`text-xs font-mono font-medium ${sev.text}`}>{expandedTechnique}</span>
                <span className="text-xs text-[color:var(--st-text-secondary)]">—</span>
                <span className="text-xs text-[color:var(--st-text-primary)]">{technique?.name || expandedTechnique}</span>
              </div>
              <span className={`text-[9px] uppercase font-medium px-1.5 py-0.5 rounded ${sev.bg} ${sev.text}`}>
                {maxSeverity(evidence)}
              </span>
            </div>

            {/* Tactics */}
            {technique && (
              <div className="px-3 py-1.5 border-b border-[color:var(--st-border)]">
                <span className="text-[10px] text-[color:var(--st-text-muted)]">Tactic: </span>
                <span className="text-[10px] text-[color:var(--st-text-muted)]">
                  {technique.tactics.map(t => TACTIC_DISPLAY_NAMES[t]).join(', ')}
                </span>
              </div>
            )}

            {/* Evidence list */}
            <div className="divide-y divide-[color:var(--st-border)]">
              {evidence.map((ev, i) => {
                const evSev = SEVERITY_COLORS[ev.finding.severity] || SEVERITY_COLORS.info;
                return (
                  <div key={i} className="px-3 py-1.5">
                    <div className="flex items-start gap-2">
                      <span className={`text-[9px] uppercase font-medium px-1 py-0.5 rounded mt-0.5 flex-shrink-0 ${evSev.bg} ${evSev.text}`}>
                        {ev.finding.severity.slice(0, 4)}
                      </span>
                      <div className="flex-1 min-w-0">
                        {showSources && (
                          <span className="text-[9px] text-blue-400 mr-1.5">[{ev.source}]</span>
                        )}
                        {(ev.sourceType === 'log-verdict' || ev.sourceType === 'log-hunting') && (
                          <span className={`text-[8px] font-medium px-1 py-0.5 rounded mr-1 ${
                            ev.sourceType === 'log-verdict'
                              ? 'bg-amber-500/15 text-amber-400'
                              : 'bg-cyan-500/15 text-cyan-400'
                          }`}>
                            {ev.sourceType === 'log-verdict' ? 'VERDICT' : 'HUNTING'}
                          </span>
                        )}
                        <span className="text-[10px] text-[color:var(--st-text-secondary)] break-words">{ev.finding.description}</span>
                      </div>
                    </div>
                    {/* Log events — show the actual events from the log */}
                    {ev.logEvents && ev.logEvents.length > 0 && (
                      <div className="ml-7 mt-1.5 space-y-1">
                        {ev.logEvents.map((le, j) => (
                          <div key={j} className="rounded border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)] px-2 py-1">
                            <p className="text-[10px] text-[color:var(--st-text-secondary)] font-mono truncate" title={le.evidence}>
                              {le.evidence.length > 120 ? le.evidence.slice(0, 120) + '...' : le.evidence}
                            </p>
                            <div className="flex items-center gap-3 mt-0.5 text-[9px] text-[color:var(--st-text-muted)]">
                              <span>{le.timestamp}</span>
                              <span>{le.eventType}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Reference link */}
            {technique && (
              <div className="px-3 py-1.5 border-t border-[color:var(--st-border)]">
                <span className="text-[10px] text-[color:var(--st-text-muted)]">Reference: </span>
                <a
                  href={technique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
                  onClick={(e) => {
                    e.preventDefault();
                    window.open(technique.url, '_blank');
                  }}
                >{technique.url}</a>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}
