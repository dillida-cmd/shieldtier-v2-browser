/**
 * AnalysisReportPanel — ANY.RUN-style tabbed behavioral sandbox report.
 * Replaces LiveSandboxPanel with 6-tab layout: Summary, Processes, Behaviors, Network, Files, Registry.
 */

import React, { useState, useMemo } from 'react';
import type { QuarantinedFile } from '../types';
import { ScoreGauge } from './SandboxResultView';
import {
  CATEGORY_META, OP_LABELS, RISK_COLORS, MITRE_MAP,
  buildProcessTree, countTreeNodes, treeDepth, formatBytes,
  type ProcessTreeNode,
} from './analysis-helpers';

type ReportTab = 'summary' | 'processes' | 'behaviors' | 'network' | 'files' | 'registry';

const TAB_DEFS: { id: ReportTab; label: string; icon: React.ReactNode }[] = [
  { id: 'summary', label: 'Summary', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg> },
  { id: 'processes', label: 'Processes', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 18 22 12"/><polyline points="8 6 2 6 2 12"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="12" y1="6" x2="12" y2="18"/></svg> },
  { id: 'behaviors', label: 'Behaviors', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> },
  { id: 'network', label: 'Network', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> },
  { id: 'files', label: 'Files', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> },
  { id: 'registry', label: 'Registry', icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg> },
];

// ═══════════════════════════════════════════════════════
// Helper: copy text to clipboard
// ═══════════════════════════════════════════════════════
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-muted)] transition-colors ml-1"
      title="Copy"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
    >
      {copied ? (
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
      ) : (
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      )}
    </button>
  );
}

// ═══════════════════════════════════════════════════════
// Main Export
// ═══════════════════════════════════════════════════════

export default function AnalysisReportPanel({ files }: { files: Map<string, QuarantinedFile> }) {
  const [activeTab, setActiveTab] = useState<ReportTab>('summary');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);

  // Collect files with behavioral analysis results, sorted by risk
  const filesWithBehavioral = useMemo(() => {
    const arr: QuarantinedFile[] = [];
    for (const [, file] of files) {
      if (file.sandboxResults.length > 0 || file.behavioralAnalysisDone) {
        arr.push(file);
      }
    }
    // Sort by sandbox score desc (most malicious first)
    arr.sort((a, b) => {
      const sa = a.sandboxResults[0]?.score ?? 0;
      const sb = b.sandboxResults[0]?.score ?? 0;
      return sb - sa;
    });
    return arr;
  }, [files]);

  // Auto-select most malicious file
  const activeFile = useMemo(() => {
    if (selectedFileId) {
      const f = filesWithBehavioral.find(f => f.id === selectedFileId);
      if (f) return f;
    }
    return filesWithBehavioral[0] || null;
  }, [filesWithBehavioral, selectedFileId]);

  // Empty state
  if (filesWithBehavioral.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-3 text-[color:var(--st-text-muted)]">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          <p className="text-sm mb-2">Behavioral Sandbox</p>
          <p className="text-xs text-[color:var(--st-text-muted)] mb-1">No files analyzed yet</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)]">Intercepted downloads are automatically analyzed with PE capability,</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)]">script detonation, shellcode emulation, and behavioral signatures</p>
        </div>
      </div>
    );
  }

  if (!activeFile) return null;

  // Extract data
  const sb = activeFile.sandboxResults[0];
  const meta = activeFile.staticAnalysis?.metadata || {} as Record<string, any>;
  const findings = activeFile.staticAnalysis?.findings || [];
  const verdictColor = sb?.verdict === 'malicious' ? 'text-red-400' : sb?.verdict === 'suspicious' ? 'text-yellow-400' : 'text-green-400';
  const verdictBg = sb?.verdict === 'malicious' ? 'border-red-500/30' : sb?.verdict === 'suspicious' ? 'border-yellow-500/30' : 'border-green-500/20';

  return (
    <div className="h-full flex flex-col bg-[color:var(--st-bg-base)]">
      {/* File selector (multi-file) */}
      {filesWithBehavioral.length > 1 && (
        <div className="px-3 pt-2 pb-1">
          <select
            value={activeFile.id}
            onChange={e => setSelectedFileId(e.target.value)}
            className="bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-2 py-1 text-xs text-[color:var(--st-text-secondary)] w-full font-mono focus:outline-none focus:border-cyan-500/40"
          >
            {filesWithBehavioral.map(f => {
              const fScore = f.sandboxResults[0]?.score;
              const fVerdict = f.sandboxResults[0]?.verdict || 'unknown';
              return (
                <option key={f.id} value={f.id}>
                  {f.originalName} — {fVerdict.toUpperCase()}{fScore !== undefined ? ` (${fScore}/100)` : ''}
                </option>
              );
            })}
          </select>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex items-center gap-1 px-3 pt-2 pb-1 border-b border-[color:var(--st-border)] overflow-x-auto">
        {TAB_DEFS.map(tab => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              aria-label={`${tab.label} tab`}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-medium transition-all whitespace-nowrap focus-visible:ring-2 focus-visible:ring-cyan-500/60 focus-visible:outline-none ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-bg-elevated)]/50 border border-transparent'
              }`}
            >
              <span className={isActive ? 'text-cyan-400' : 'text-[color:var(--st-text-muted)]'}>{tab.icon}</span>
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === 'summary' && <SummaryTab file={activeFile} sb={sb} meta={meta} findings={findings} verdictColor={verdictColor} verdictBg={verdictBg} />}
        {activeTab === 'processes' && <ProcessesTab file={activeFile} meta={meta} sb={sb} />}
        {activeTab === 'behaviors' && <BehaviorsTab findings={findings} />}
        {activeTab === 'network' && <NetworkTab meta={meta} findings={findings} />}
        {activeTab === 'files' && <FilesTab meta={meta} findings={findings} />}
        {activeTab === 'registry' && <RegistryTab meta={meta} findings={findings} />}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Summary Tab
// ═══════════════════════════════════════════════════════

function SummaryTab({ file, sb, meta, findings, verdictColor, verdictBg }: {
  file: QuarantinedFile; sb: any; meta: Record<string, any>;
  findings: any[]; verdictColor: string; verdictBg: string;
}) {
  const behaviorSummary: string[] = meta.behaviorSummary || [];
  const scoreBreakdown: Record<string, number> = sb?.details?.scoreBreakdown || {};
  const categories: Record<string, number> = sb?.details?.categories || {};
  const mitreTechniques: string[] = sb?.details?.mitreTechniques || [];

  // Also collect MITRE from category keys
  const catMitre = Object.keys(categories).map(c => MITRE_MAP[c]).filter(Boolean);
  const allMitre = [...new Set([...mitreTechniques, ...catMitre])];

  return (
    <div className="p-3 space-y-4">
      {/* File header with hashes */}
      <div className={`bg-[color:var(--st-bg-panel)] rounded-lg border ${verdictBg} p-3`}>
        <div className="flex items-start gap-3 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${file.riskLevel === 'critical' ? 'bg-red-500 animate-pulse' : file.riskLevel === 'high' ? 'bg-orange-500' : file.riskLevel === 'medium' ? 'bg-yellow-500' : 'bg-green-500'}`} />
              <span className="text-[color:var(--st-text-primary)] text-sm font-mono font-bold truncate">{file.originalName}</span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[10px] text-[color:var(--st-text-muted)] mt-1">
              <span>Type: <span className="text-[color:var(--st-text-secondary)]">{file.staticAnalysis?.fileType || 'unknown'}</span></span>
              <span>Size: <span className="text-[color:var(--st-text-secondary)]">{formatBytes(file.fileSize)}</span></span>
              {file.staticAnalysis?.entropy !== undefined && (
                <span>Entropy: <span className={`${file.staticAnalysis.entropy > 7 ? 'text-red-400' : 'text-[color:var(--st-text-secondary)]'}`}>{file.staticAnalysis.entropy.toFixed(2)}</span></span>
              )}
            </div>
          </div>
        </div>

        {/* Hashes */}
        {file.hashes && (
          <div className="space-y-1 bg-black/30 rounded p-2 font-mono text-[10px]">
            <div className="flex items-center gap-2">
              <span className="text-[color:var(--st-text-muted)] w-10 shrink-0">SHA256</span>
              <span className="text-[color:var(--st-text-muted)] truncate select-all">{file.hashes.sha256}</span>
              <CopyButton text={file.hashes.sha256} />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[color:var(--st-text-muted)] w-10 shrink-0">MD5</span>
              <span className="text-[color:var(--st-text-muted)] truncate select-all">{file.hashes.md5}</span>
              <CopyButton text={file.hashes.md5} />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[color:var(--st-text-muted)] w-10 shrink-0">SHA1</span>
              <span className="text-[color:var(--st-text-muted)] truncate select-all">{file.hashes.sha1}</span>
              <CopyButton text={file.hashes.sha1} />
            </div>
          </div>
        )}
      </div>

      {/* Verdict + Score */}
      {sb && (
        <div className="flex items-start gap-4">
          {sb.score !== undefined && <ScoreGauge score={sb.score} />}
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2">
              <span className={`font-bold uppercase text-lg tracking-wide ${verdictColor}`}>{sb.verdict || 'unknown'}</span>
              {sb.score !== undefined && (
                <span className={`text-sm font-mono ${sb.score >= 60 ? 'text-red-400' : sb.score >= 30 ? 'text-yellow-400' : 'text-green-400'}`}>{sb.score}/100</span>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5 text-[10px]">
              <span className="text-[color:var(--st-text-muted)]">Findings: <span className="text-[color:var(--st-text-secondary)]">{findings.length}</span></span>
              {meta.peCapability && <span className="text-[color:var(--st-text-muted)]">Imports: <span className="text-[color:var(--st-text-secondary)]">{meta.peCapability.importCount}</span></span>}
              {meta.detonation && <span className="text-[color:var(--st-text-muted)]">Operations: <span className="text-[color:var(--st-text-secondary)]">{meta.detonation.operationCount}</span></span>}
              {meta.emulation && <span className="text-[color:var(--st-text-muted)]">Instructions: <span className="text-[color:var(--st-text-secondary)]">{meta.emulation.instructionsExecuted}</span></span>}
            </div>
          </div>
        </div>
      )}

      {/* MITRE + Category pills */}
      {(allMitre.length > 0 || Object.keys(categories).length > 0) && (
        <div className="flex flex-wrap gap-1.5">
          {Object.keys(categories).map(cat => {
            const cm = CATEGORY_META[cat] || CATEGORY_META.UNKNOWN;
            return <span key={cat} className={`${cm.bg} ${cm.color} px-2 py-0.5 rounded text-[10px] font-medium`}>{cat}</span>;
          })}
          {allMitre.map(t => (
            <span key={t} className="bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded text-[10px] font-medium">{t}</span>
          ))}
        </div>
      )}

      {/* What This File Does */}
      {behaviorSummary.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg p-3 border border-[color:var(--st-border)]">
          <p className="text-[color:var(--st-text-muted)] text-[10px] font-semibold mb-2 uppercase tracking-wider">What This File Does</p>
          <ul className="space-y-1.5">
            {behaviorSummary.map((line, i) => (
              <li key={i} className="text-[color:var(--st-text-secondary)] text-[11px] flex items-start gap-2">
                <span className="text-cyan-500 mt-0.5 shrink-0">&#9656;</span>
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Score Breakdown */}
      {Object.keys(scoreBreakdown).length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg p-3 border border-[color:var(--st-border)]">
          <p className="text-[color:var(--st-text-muted)] text-[10px] font-semibold mb-2 uppercase tracking-wider">Score Breakdown</p>
          <div className="space-y-1.5">
            {Object.entries(scoreBreakdown)
              .filter(([, v]) => v > 0)
              .sort(([, a], [, b]) => b - a)
              .map(([label, pts]) => {
                const barWidth = Math.min(100, (pts / 30) * 100);
                const barColor = pts >= 20 ? 'bg-red-500' : pts >= 10 ? 'bg-yellow-500' : 'bg-cyan-500';
                return (
                  <div key={label} className="flex items-center gap-2">
                    <span className="text-[color:var(--st-text-muted)] text-[10px] w-32 shrink-0 truncate">{label}</span>
                    <div className="flex-1 h-2 bg-[color:var(--st-bg-elevated)] rounded overflow-hidden">
                      <div className={`h-full ${barColor} rounded transition-all`} style={{ width: `${barWidth}%` }} />
                    </div>
                    <span className="text-[color:var(--st-text-muted)] text-[10px] w-8 text-right font-mono">+{pts}</span>
                  </div>
                );
              })}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Processes Tab
// ═══════════════════════════════════════════════════════

function ProcessesTab({ file, meta, sb }: { file: QuarantinedFile; meta: Record<string, any>; sb: any }) {
  const det = meta.detonation;
  const emu = meta.emulation;

  // Use full operations if available, fall back to topOperations
  const detOps = det?.operations || det?.topOperations || [];
  const emuCalls = emu?.apiCalls || emu?.topApiCalls || [];

  const processTree = buildProcessTree(file.originalName, detOps, emuCalls);
  const hasTree = processTree.children.length > 0;

  const mitreTechniques: string[] = sb?.details?.mitreTechniques || [];

  if (!hasTree) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mx-auto mb-2 text-[color:var(--st-text-muted)]"><polyline points="16 18 22 18 22 12"/><polyline points="8 6 2 6 2 12"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="12" y1="6" x2="12" y2="18"/></svg>
          <p className="text-xs">No process activity detected</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-3">
      <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
        {/* Tree header */}
        <div className="flex items-center justify-between px-3 py-2 bg-[color:var(--st-bg-elevated)] border-b border-[color:var(--st-border)]">
          <span className="text-[color:var(--st-text-primary)] text-[11px] font-mono font-bold">{file.originalName}</span>
          <div className="flex items-center gap-1.5">
            {sb?.score !== undefined && (
              <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                sb.score >= 60 ? 'bg-red-500/20 text-red-400' : sb.score >= 30 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
              }`}>RISK {sb.score}%</span>
            )}
            {mitreTechniques.slice(0, 5).map(t => (
              <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-medium">{t}</span>
            ))}
          </div>
        </div>
        {/* Tree metadata */}
        <div className="px-3 py-1.5 text-[10px] text-[color:var(--st-text-muted)] border-b border-[color:var(--st-border)]/50">
          Depth: {treeDepth(processTree)} | Nodes: {countTreeNodes(processTree)}{emu?.selfModifying ? ' | Self-Modifying' : ''}
        </div>
        {/* Tree body */}
        <div className="px-3 py-2">
          <TreeNode node={processTree} depth={0} isLast={true} />
        </div>
      </div>
    </div>
  );
}

function TreeNode({ node, depth, isLast }: { node: ProcessTreeNode; depth: number; isLast: boolean }) {
  return (
    <div className="relative">
      <div className="flex items-start py-[3px]" style={{ paddingLeft: `${depth * 20}px` }}>
        {depth > 0 && (
          <>
            <span
              className="absolute border-l-2 border-amber-500/40"
              style={{ left: `${(depth - 1) * 20 + 7}px`, top: 0, bottom: isLast ? '50%' : 0 }}
            />
            <span
              className="absolute border-t-2 border-amber-500/40"
              style={{ left: `${(depth - 1) * 20 + 7}px`, top: '11px', width: '10px' }}
            />
          </>
        )}
        <span className="text-[color:var(--st-text-primary)] font-mono font-bold text-[11px] shrink-0 bg-[color:var(--st-bg-elevated)] px-1 rounded relative z-10">{node.name}</span>
        {node.source && (
          <span className={`text-[8px] ml-1.5 px-1 py-0.5 rounded shrink-0 ${node.source === 'detonation' ? 'bg-orange-500/15 text-orange-400' : 'bg-cyan-500/15 text-cyan-400'}`}>
            {node.source === 'detonation' ? 'DET' : 'EMU'}
          </span>
        )}
        <span className="text-[color:var(--st-text-muted)] font-mono text-[10px] ml-2 truncate">{node.cmdline}</span>
      </div>
      {node.children.map((child, i) => (
        <TreeNode key={`${child.name}-${i}`} node={child} depth={depth + 1} isLast={i === node.children.length - 1} />
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Behaviors Tab — ANY.RUN style three-tier grouping
// ═══════════════════════════════════════════════════════

function BehaviorsTab({ findings }: { findings: any[] }) {
  const tiers = useMemo(() => {
    const malicious: any[] = [];
    const suspicious: any[] = [];
    const info: any[] = [];

    for (const f of findings) {
      if (f.severity === 'critical' || f.severity === 'high') malicious.push(f);
      else if (f.severity === 'medium') suspicious.push(f);
      else info.push(f);
    }

    return { malicious, suspicious, info };
  }, [findings]);

  if (findings.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mx-auto mb-2 text-[color:var(--st-text-muted)]"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <p className="text-xs">No behavioral findings</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-3">
      {tiers.malicious.length > 0 && (
        <BehaviorTierGroup label="MALICIOUS" count={tiers.malicious.length} color="red" findings={tiers.malicious} />
      )}
      {tiers.suspicious.length > 0 && (
        <BehaviorTierGroup label="SUSPICIOUS" count={tiers.suspicious.length} color="yellow" findings={tiers.suspicious} />
      )}
      {tiers.info.length > 0 && (
        <BehaviorTierGroup label="INFO" count={tiers.info.length} color="gray" findings={tiers.info} />
      )}
    </div>
  );
}

function BehaviorTierGroup({ label, count, color, findings }: { label: string; count: number; color: 'red' | 'yellow' | 'gray'; findings: any[] }) {
  const [expanded, setExpanded] = useState(true);
  const colorMap = {
    red:    { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', dot: 'bg-red-500', badge: 'bg-red-500/20 text-red-400' },
    yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-500', badge: 'bg-yellow-500/20 text-yellow-400' },
    gray:   { bg: 'bg-gray-500/5', border: 'border-[color:var(--st-border)]', text: 'text-gray-400', dot: 'bg-gray-500', badge: 'bg-gray-500/20 text-gray-400' },
  };
  const c = colorMap[color];

  return (
    <div className={`rounded-lg border ${c.border} overflow-hidden`}>
      <button onClick={() => setExpanded(!expanded)} aria-expanded={expanded} className={`w-full flex items-center gap-2 px-3 py-2 focus-visible:ring-2 focus-visible:ring-cyan-500/60 focus-visible:outline-none ${c.bg}`}>
        <svg width="8" height="8" viewBox="0 0 8 8" className={`text-[color:var(--st-text-muted)] transition-transform ${expanded ? 'rotate-90' : ''}`}>
          <path d="M2 1l4 3-4 3z" fill="currentColor" />
        </svg>
        <span className={`${c.dot} w-2 h-2 rounded-full`} />
        <span className={`${c.text} text-[11px] font-bold tracking-wider`}>{label}</span>
        <span className={`${c.badge} text-[9px] px-1.5 py-0.5 rounded font-bold ml-auto`}>{count}</span>
      </button>
      {expanded && (
        <div className="divide-y divide-[color:var(--st-border)]/50">
          {findings.map((f, i) => {
            const fc = RISK_COLORS[f.severity] || RISK_COLORS.unknown;
            const cm = CATEGORY_META[f.category?.toUpperCase()] || CATEGORY_META.UNKNOWN;
            return (
              <div key={i} className="px-3 py-2 hover:bg-white/[0.02] transition-colors">
                <div className="flex items-start gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${fc.dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`${fc.text} text-[11px] font-medium`}>{f.name || f.rule || f.category}</span>
                      <span className={`${cm.bg} ${cm.color} px-1.5 py-0.5 rounded text-[8px] font-medium`}>{f.category}</span>
                      {f.mitre && <span className="bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded text-[8px] font-medium">{f.mitre}</span>}
                    </div>
                    {f.description && <p className="text-[color:var(--st-text-muted)] text-[10px] mt-0.5">{f.description}</p>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Network Tab
// ═══════════════════════════════════════════════════════

function NetworkTab({ meta, findings }: { meta: Record<string, any>; findings: any[] }) {
  const det = meta.detonation;
  const emu = meta.emulation;

  // Collect HTTP requests from full operations
  const httpRequests = useMemo(() => {
    const reqs: { method: string; url: string; data?: string }[] = [];
    const ops = det?.operations || det?.topOperations || [];
    for (const op of ops) {
      if (op.type === 'network_request' || op.type === 'download') {
        reqs.push({ method: op.method || 'GET', url: op.target, data: op.data });
      }
    }
    // Add from networkAttemptsDetail
    if (det?.networkAttemptsDetail) {
      for (const n of det.networkAttemptsDetail) {
        if (!reqs.some(r => r.url === n.url)) {
          reqs.push({ method: n.method || 'GET', url: n.url, data: n.data });
        }
      }
    }
    return reqs;
  }, [det]);

  // DNS resolutions
  const dnsOps = useMemo(() => {
    const dns: { hostname: string; ip?: string }[] = [];
    const ops = det?.operations || det?.topOperations || [];
    for (const op of ops) {
      if (op.type === 'dns_resolve') {
        dns.push({ hostname: op.target, ip: op.data });
      }
    }
    // From INetSim traffic
    if (det?.networkTraffic?.dnsResolutions) {
      for (const d of det.networkTraffic.dnsResolutions) {
        if (!dns.some(x => x.hostname === d.hostname)) {
          dns.push(d);
        }
      }
    }
    return dns;
  }, [det]);

  // Network URLs from emulation memory
  const emuNetworks: string[] = emu?.networksFound || [];

  // INetSim traffic summary
  const inetSim = det?.networkTraffic || emu?.networkTraffic;

  // Protocol counts
  const protocols: Record<string, number> = inetSim?.protocols || {};

  const hasContent = httpRequests.length > 0 || dnsOps.length > 0 || emuNetworks.length > 0 || inetSim;

  if (!hasContent) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mx-auto mb-2 text-[color:var(--st-text-muted)]"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>
          <p className="text-xs">No network activity detected</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-3">
      {/* Protocol summary */}
      {(Object.keys(protocols).length > 0 || httpRequests.length > 0 || dnsOps.length > 0) && (
        <div className="flex flex-wrap gap-2">
          {httpRequests.length > 0 && (
            <div className="bg-[color:var(--st-bg-panel)] rounded px-3 py-1.5 border border-[color:var(--st-border)] text-[10px]">
              <span className="text-[color:var(--st-text-muted)]">HTTP</span> <span className="text-[color:var(--st-text-secondary)] font-mono font-bold">{httpRequests.length}</span>
            </div>
          )}
          {dnsOps.length > 0 && (
            <div className="bg-[color:var(--st-bg-panel)] rounded px-3 py-1.5 border border-[color:var(--st-border)] text-[10px]">
              <span className="text-[color:var(--st-text-muted)]">DNS</span> <span className="text-[color:var(--st-text-secondary)] font-mono font-bold">{dnsOps.length}</span>
            </div>
          )}
          {Object.entries(protocols).map(([proto, count]) => (
            <div key={proto} className="bg-[color:var(--st-bg-panel)] rounded px-3 py-1.5 border border-[color:var(--st-border)] text-[10px]">
              <span className="text-[color:var(--st-text-muted)]">{proto.toUpperCase()}</span> <span className="text-[color:var(--st-text-secondary)] font-mono font-bold">{count}</span>
            </div>
          ))}
        </div>
      )}

      {/* HTTP Requests */}
      {httpRequests.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
          <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
            <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">HTTP Requests</span>
          </div>
          <div className="divide-y divide-[color:var(--st-border)]/50 max-h-64 overflow-y-auto">
            {httpRequests.map((req, i) => (
              <div key={i} className="px-3 py-2 flex items-start gap-2">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                  req.method === 'POST' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                }`}>{req.method}</span>
                <span className="text-red-400 text-[11px] font-mono truncate select-all" title={req.url}>{req.url}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DNS Resolutions */}
      {dnsOps.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
          <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
            <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">DNS Resolutions</span>
          </div>
          <div className="divide-y divide-[color:var(--st-border)]/50 max-h-48 overflow-y-auto">
            {dnsOps.map((dns, i) => (
              <div key={i} className="px-3 py-1.5 flex items-center gap-3 text-[11px] font-mono">
                <span className="text-[color:var(--st-text-secondary)] truncate" title={dns.hostname}>{dns.hostname}</span>
                <span className="text-[color:var(--st-text-muted)] shrink-0">&rarr;</span>
                <span className="text-cyan-400 shrink-0">{dns.ip || 'unresolved'}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Network URLs from emulation memory */}
      {emuNetworks.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-red-500/20 overflow-hidden">
          <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
            <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">Extracted from Memory (Emulation)</span>
          </div>
          <div className="p-2 space-y-0.5 max-h-32 overflow-y-auto font-mono text-[10px]">
            {emuNetworks.map((net, i) => (
              <div key={i} className="text-red-400 truncate select-all" title={net}>{net}</div>
            ))}
          </div>
        </div>
      )}

      {/* INetSim traffic stats */}
      {inetSim && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] p-3">
          <p className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider mb-2">INetSim Traffic Summary</p>
          <div className="grid grid-cols-3 gap-2 text-[10px]">
            <div><span className="text-[color:var(--st-text-muted)]">Total Requests:</span> <span className="text-[color:var(--st-text-secondary)] font-mono">{inetSim.totalRequests}</span></div>
            <div><span className="text-[color:var(--st-text-muted)]">Unique Hosts:</span> <span className="text-[color:var(--st-text-secondary)] font-mono">{inetSim.uniqueHostnames?.length || 0}</span></div>
            <div><span className="text-[color:var(--st-text-muted)]">Errors:</span> <span className="text-[color:var(--st-text-secondary)] font-mono">{inetSim.errorResponses || 0}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Files Tab
// ═══════════════════════════════════════════════════════

function FilesTab({ meta, findings }: { meta: Record<string, any>; findings: any[] }) {
  const det = meta.detonation;
  const pe = meta.peCapability;

  // Collect file operations from detonation
  const fileOps = useMemo(() => {
    const ops: { type: string; target: string; data?: string }[] = [];
    const allOps = det?.operations || det?.topOperations || [];
    for (const op of allOps) {
      if (['file_write', 'file_read', 'file_delete', 'file_execute'].includes(op.type)) {
        ops.push(op);
      }
    }
    return ops;
  }, [det]);

  // Embedded resources from PE
  const resources = pe?.embeddedResourceDetails || [];

  // Stats
  const execCount = fileOps.filter(o => o.type === 'file_execute').length;
  const writeCount = fileOps.filter(o => o.type === 'file_write').length;
  const readCount = fileOps.filter(o => o.type === 'file_read').length;
  const deleteCount = fileOps.filter(o => o.type === 'file_delete').length;

  const isSuspiciousExt = (path: string) => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|hta)$/i.test(path);
  const suspiciousCount = fileOps.filter(o => isSuspiciousExt(o.target)).length;

  const hasContent = fileOps.length > 0 || resources.length > 0;

  if (!hasContent) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mx-auto mb-2 text-[color:var(--st-text-muted)]"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          <p className="text-xs">No file operations detected</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-3">
      {/* Stats bar */}
      {fileOps.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {writeCount > 0 && <StatBadge label="Write" count={writeCount} color="cyan" />}
          {readCount > 0 && <StatBadge label="Read" count={readCount} color="blue" />}
          {execCount > 0 && <StatBadge label="Execute" count={execCount} color="red" />}
          {deleteCount > 0 && <StatBadge label="Delete" count={deleteCount} color="orange" />}
          {suspiciousCount > 0 && <StatBadge label="Suspicious" count={suspiciousCount} color="yellow" />}
        </div>
      )}

      {/* File operation cards */}
      {fileOps.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
          <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
            <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">File Operations</span>
          </div>
          <div className="divide-y divide-[color:var(--st-border)]/50 max-h-72 overflow-y-auto">
            {fileOps.map((op, i) => {
              const label = OP_LABELS[op.type] || op.type;
              const isExec = op.type === 'file_execute';
              const isDel = op.type === 'file_delete';
              const badgeColor = isExec ? 'bg-red-500/20 text-red-400' : isDel ? 'bg-orange-500/20 text-orange-400' : op.type === 'file_write' ? 'bg-cyan-500/20 text-cyan-400' : 'bg-blue-500/20 text-blue-400';
              return (
                <div key={i} className="px-3 py-2 flex items-start gap-2">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 ${badgeColor}`}>{label.toUpperCase()}</span>
                  <div className="min-w-0">
                    <span className="text-[color:var(--st-text-secondary)] text-[11px] font-mono truncate block">{op.target}</span>
                    {op.data && <span className="text-[color:var(--st-text-muted)] text-[10px] truncate block">{op.data.substring(0, 120)}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* PE Embedded Resources */}
      {resources.length > 0 && (
        <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
          <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
            <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">Embedded Resources</span>
            <span className="text-[color:var(--st-text-muted)] text-[9px] ml-2">{resources.length} resource{resources.length !== 1 ? 's' : ''}</span>
          </div>
          <div className="divide-y divide-[color:var(--st-border)]/50 max-h-48 overflow-y-auto">
            {resources.map((r: any, i: number) => {
              const isHighEntropy = r.entropy > 7;
              const isExecType = r.type === 'PE' || r.type === 'script';
              return (
                <div key={i} className="px-3 py-2 flex items-center gap-3">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                    isExecType ? 'bg-red-500/20 text-red-400' : 'bg-gray-500/20 text-gray-400'
                  }`}>{r.type}</span>
                  <span className="text-[color:var(--st-text-secondary)] text-[11px] font-mono truncate">{r.name}</span>
                  <span className="text-[color:var(--st-text-muted)] text-[10px] shrink-0">{formatBytes(r.size)}</span>
                  {/* Entropy gauge */}
                  <div className="w-16 h-1.5 bg-[color:var(--st-bg-elevated)] rounded overflow-hidden shrink-0" title={`Entropy: ${r.entropy.toFixed(2)}`}>
                    <div className={`h-full rounded ${isHighEntropy ? 'bg-red-500' : r.entropy > 5 ? 'bg-yellow-500' : 'bg-green-500'}`} style={{ width: `${(r.entropy / 8) * 100}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Registry Tab
// ═══════════════════════════════════════════════════════

function RegistryTab({ meta, findings }: { meta: Record<string, any>; findings: any[] }) {
  const det = meta.detonation;

  // Collect registry operations from detonation
  const regOps = useMemo(() => {
    const ops: { type: string; target: string; data?: string }[] = [];
    const allOps = det?.operations || det?.topOperations || [];
    for (const op of allOps) {
      if (['registry_read', 'registry_write', 'registry_delete'].includes(op.type)) {
        ops.push(op);
      }
    }
    return ops;
  }, [det]);

  const readCount = regOps.filter(o => o.type === 'registry_read').length;
  const writeCount = regOps.filter(o => o.type === 'registry_write').length;
  const deleteCount = regOps.filter(o => o.type === 'registry_delete').length;

  if (regOps.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-[color:var(--st-text-muted)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" className="mx-auto mb-2 text-[color:var(--st-text-muted)]"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
          <p className="text-xs">No registry activity detected</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-3">
      {/* Stats bar */}
      <div className="flex flex-wrap gap-2">
        {readCount > 0 && <StatBadge label="Read" count={readCount} color="blue" />}
        {writeCount > 0 && <StatBadge label="Write" count={writeCount} color="yellow" />}
        {deleteCount > 0 && <StatBadge label="Delete" count={deleteCount} color="red" />}
      </div>

      {/* Registry operation cards */}
      <div className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
        <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)]">
          <span className="text-[color:var(--st-text-muted)] text-[10px] font-semibold uppercase tracking-wider">Registry Operations</span>
        </div>
        <div className="divide-y divide-[color:var(--st-border)]/50 max-h-80 overflow-y-auto">
          {regOps.map((op, i) => {
            const label = OP_LABELS[op.type] || op.type;
            const badgeColor = op.type === 'registry_write' ? 'bg-yellow-500/20 text-yellow-400' : op.type === 'registry_delete' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400';
            return (
              <div key={i} className="px-3 py-2 flex items-start gap-2">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 uppercase ${badgeColor}`}>{label}</span>
                <div className="min-w-0">
                  <span className="text-[color:var(--st-text-secondary)] text-[11px] font-mono truncate block">{op.target}</span>
                  {op.data && <span className="text-[color:var(--st-text-muted)] text-[10px] truncate block">{op.data.substring(0, 200)}</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Shared sub-components
// ═══════════════════════════════════════════════════════

function StatBadge({ label, count, color }: { label: string; count: number; color: 'red' | 'orange' | 'yellow' | 'blue' | 'cyan' | 'green' | 'gray' }) {
  const colorMap: Record<string, string> = {
    red: 'bg-red-500/15 text-red-400 border-red-500/20',
    orange: 'bg-orange-500/15 text-orange-400 border-orange-500/20',
    yellow: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
    blue: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
    cyan: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/20',
    green: 'bg-green-500/15 text-green-400 border-green-500/20',
    gray: 'bg-gray-500/15 text-gray-400 border-gray-500/20',
  };
  return (
    <div className={`rounded px-2.5 py-1 border text-[10px] font-medium ${colorMap[color]}`}>
      {label}: <span className="font-mono font-bold">{count}</span>
    </div>
  );
}
