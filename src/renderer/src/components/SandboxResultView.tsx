import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

interface SandboxResultViewProps {
  details: Record<string, any>;
  verdict?: string;
  score?: number;
}

interface Signature {
  id: string;
  name: string;
  severity: string;
  evidence: string[];
  mitre?: string;
}

interface AdvancedFinding {
  source: string;
  severity: string;
  category: string;
  description: string;
  mitre?: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: 'target' | 'category' | 'signature' | 'mitre' | 'network' | 'script' | 'advanced' | 'cluster';
  severity?: string;
  source?: string;
  x: number;
  y: number;
  detail?: string;
  children?: string[];
  count?: number;
}

interface GraphEdge {
  from: string;
  to: string;
  type: 'primary' | 'secondary' | 'mitre';
  severity?: string;
}

// ═══════════════════════════════════════════════════════════════
// Severity Colors (matches MITREMappingTab)
// ═══════════════════════════════════════════════════════════════

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string; hex: string }> = {
  critical: { bg: 'bg-red-600/20', text: 'text-red-400', border: 'border-red-500/30', hex: '#ef4444' },
  high:     { bg: 'bg-orange-600/20', text: 'text-orange-400', border: 'border-orange-500/30', hex: '#f97316' },
  medium:   { bg: 'bg-yellow-600/20', text: 'text-yellow-400', border: 'border-yellow-500/30', hex: '#eab308' },
  low:      { bg: 'bg-blue-600/20', text: 'text-blue-400', border: 'border-blue-500/30', hex: '#3b82f6' },
  info:     { bg: 'bg-gray-600/20', text: 'text-gray-400', border: 'border-gray-500/30', hex: '#6b7280' },
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0,
};

const getSevColor = (sev: string) => SEVERITY_COLORS[sev] || SEVERITY_COLORS.info;

// ═══════════════════════════════════════════════════════════════
// Score Gauge (SVG arc)
// ═══════════════════════════════════════════════════════════════

export function ScoreGauge({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score));
  const color = clamped <= 30 ? '#22c55e' : clamped <= 70 ? '#eab308' : '#ef4444';
  const circlePath = 'M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831';

  return (
    <div className="relative w-16 h-16 shrink-0">
      <svg viewBox="0 0 36 36" className="w-full h-full">
        {/* Background circle */}
        <path d={circlePath} fill="none" stroke="#1e293b" strokeWidth="3" />
        {/* Score circle */}
        <path
          d={circlePath}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeDasharray={`${clamped}, 100`}
          strokeLinecap="round"
        />
      </svg>
      {/* Centered score text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-base font-bold font-mono leading-none" style={{ color }}>{clamped}</span>
        <span className="text-[8px] text-[color:var(--st-text-muted)] font-mono leading-none">/100</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Collapsible Section
// ═══════════════════════════════════════════════════════════════

function Section({ title, icon, count, defaultOpen = true, accent, children }: {
  title: string;
  icon: string;
  count?: number;
  defaultOpen?: boolean;
  accent?: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`rounded-lg border ${accent ? `border-${accent}-500/20` : 'border-[color:var(--st-border)]'} bg-[color:var(--st-bg-panel)] overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-white/[0.02] transition-colors"
      >
        <span className="text-[11px] text-[color:var(--st-text-muted)] transition-transform" style={{ transform: open ? 'rotate(90deg)' : 'rotate(0deg)' }}>&#9654;</span>
        <span className="text-[10px]">{icon}</span>
        <span className="text-[color:var(--st-text-secondary)] text-[11px] font-medium flex-1">{title}</span>
        {count !== undefined && (
          <span className="text-[9px] text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-elevated)] rounded px-1.5 py-0.5">{count}</span>
        )}
      </button>
      {open && <div className="px-3 pb-3 pt-1">{children}</div>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Severity Pill
// ═══════════════════════════════════════════════════════════════

function SeverityPill({ severity }: { severity: string }) {
  const c = getSevColor(severity);
  return (
    <span className={`inline-block text-[9px] px-1.5 py-0.5 rounded ${c.bg} ${c.text} border ${c.border} capitalize`}>
      {severity}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════
// Horizontal Bar (0-100)
// ═══════════════════════════════════════════════════════════════

function HBar({ value, max = 100, color = '#a855f7' }: { value: number; max?: number; color?: string }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="h-2 rounded-full bg-[color:var(--st-bg-elevated)] overflow-hidden w-full">
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Report View
// ═══════════════════════════════════════════════════════════════

function ReportView({ details, verdict, score }: SandboxResultViewProps) {
  const [expandedSigs, setExpandedSigs] = useState<Set<string>>(new Set());

  const signatures: Signature[] = details.signatures || [];
  const scriptAnalysis = details.scriptAnalysis || {};
  const networkAnalysis = details.networkAnalysis || {};
  const summaryBullets: string[] = details.summary || [];
  const advancedFindings: AdvancedFinding[] = details.advancedFindings || [];
  const artifactqlFindings = details.artifactqlFindings as { matches: any[]; artifactsEvaluated: number; totalTimeMs: number } | undefined;

  // Group signatures by severity
  const sigsBySeverity = useMemo(() => {
    const groups: Record<string, Signature[]> = {};
    for (const sig of signatures) {
      const sev = sig.severity || 'info';
      (groups[sev] ||= []).push(sig);
    }
    return Object.entries(groups).sort(
      ([a], [b]) => (SEVERITY_ORDER[b] || 0) - (SEVERITY_ORDER[a] || 0)
    );
  }, [signatures]);

  // Group advanced findings by source
  const advancedBySource = useMemo(() => {
    const groups: Record<string, AdvancedFinding[]> = {};
    for (const f of advancedFindings) {
      (groups[f.source] ||= []).push(f);
    }
    return Object.entries(groups);
  }, [advancedFindings]);

  const toggleSig = (id: string) => {
    setExpandedSigs(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const verdictColor = verdict === 'malicious' ? 'text-red-400' : verdict === 'clean' ? 'text-green-400' : 'text-yellow-400';

  return (
    <div className="space-y-2">
      {/* ── Verdict Header ── */}
      <div className="flex items-center gap-4 p-3 rounded-lg bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)]">
        {score !== undefined && <ScoreGauge score={score} />}
        <div className="flex-1 min-w-0 space-y-1">
          {verdict && (
            <div className="flex items-center gap-2">
              <span className={`text-sm font-semibold capitalize ${verdictColor}`}>{verdict}</span>
              <span className="text-[9px] text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-elevated)] rounded px-1.5 py-0.5">
                {details.engine || 'Sandbox'}
              </span>
            </div>
          )}
          {details.pageUrl && (
            <p className="text-[10px] text-[color:var(--st-text-muted)] truncate" title={details.pageUrl}>
              {details.pageUrl}
            </p>
          )}
          <div className="flex items-center gap-3 text-[10px] text-[color:var(--st-text-muted)]">
            {details.signaturesChecked !== undefined && (
              <span>{details.signaturesFired}/{details.signaturesChecked} sigs fired</span>
            )}
            {details.analysisTimeMs !== undefined && (
              <span>{(details.analysisTimeMs / 1000).toFixed(1)}s</span>
            )}
          </div>
        </div>
      </div>

      {/* ── Behavior Summary ── */}
      {summaryBullets.length > 0 && (
        <Section title="Behavior Summary" icon="&#128270;" count={summaryBullets.length}>
          <ul className="space-y-1">
            {summaryBullets.map((bullet, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] text-[color:var(--st-text-muted)]">
                <span className="text-blue-400 mt-0.5 shrink-0">&#8226;</span>
                <span>{bullet}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* ── Signatures ── */}
      {signatures.length > 0 && (
        <Section title="Signatures" icon="&#9888;" count={signatures.length} accent="red">
          <div className="space-y-2">
            {sigsBySeverity.map(([sev, sigs]) => (
              <div key={sev}>
                <div className="flex items-center gap-2 mb-1.5">
                  <SeverityPill severity={sev} />
                  <span className="text-[9px] text-[color:var(--st-text-muted)]">{sigs.length} match{sigs.length > 1 ? 'es' : ''}</span>
                </div>
                <div className="space-y-1 ml-1">
                  {sigs.map(sig => {
                    const isExpanded = expandedSigs.has(sig.id);
                    return (
                      <div key={sig.id} className={`rounded border ${getSevColor(sev).border} ${getSevColor(sev).bg} overflow-hidden`}>
                        <button
                          onClick={() => toggleSig(sig.id)}
                          className="w-full flex items-center gap-2 px-2 py-1.5 text-left"
                        >
                          <span className="text-[9px] text-[color:var(--st-text-muted)]" style={{ transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)', display: 'inline-block', transition: 'transform 0.15s' }}>&#9654;</span>
                          <span className={`text-[11px] ${getSevColor(sev).text} flex-1 truncate`}>{sig.name}</span>
                          <span className="text-[8px] text-[color:var(--st-text-muted)] font-mono shrink-0">{sig.id}</span>
                          {sig.mitre && (
                            <span className="text-[8px] text-purple-400 bg-purple-600/15 rounded px-1 py-0.5 shrink-0">{sig.mitre}</span>
                          )}
                        </button>
                        {isExpanded && sig.evidence.length > 0 && (
                          <div className="px-2 pb-2 pt-0.5 border-t border-[color:var(--st-border-subtle)]">
                            <p className="text-[9px] text-[color:var(--st-text-muted)] mb-1">Evidence:</p>
                            {sig.evidence.map((ev, j) => (
                              <p key={j} className="text-[10px] text-[color:var(--st-text-muted)] font-mono ml-2 break-all">{ev}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Script Analysis ── */}
      {(scriptAnalysis.obfuscationScore !== undefined || scriptAnalysis.evalCount !== undefined) && (
        <Section title="Script Analysis" icon="&#128736;" accent="purple">
          <div className="space-y-2">
            {scriptAnalysis.obfuscationScore !== undefined && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-[color:var(--st-text-muted)]">Obfuscation Score</span>
                  <span className="text-[10px] text-purple-400 font-medium">{scriptAnalysis.obfuscationScore}/100</span>
                </div>
                <HBar value={scriptAnalysis.obfuscationScore} />
              </div>
            )}
            <div className="flex flex-wrap gap-3">
              {scriptAnalysis.evalCount !== undefined && (
                <div className="text-center">
                  <p className="text-purple-400 text-sm font-semibold">{scriptAnalysis.evalCount}</p>
                  <p className="text-[9px] text-[color:var(--st-text-muted)]">eval() calls</p>
                </div>
              )}
              {scriptAnalysis.dynamicScriptCount !== undefined && (
                <div className="text-center">
                  <p className="text-purple-400 text-sm font-semibold">{scriptAnalysis.dynamicScriptCount}</p>
                  <p className="text-[9px] text-[color:var(--st-text-muted)]">Dynamic scripts</p>
                </div>
              )}
            </div>
            {scriptAnalysis.detectedPackers?.length > 0 && (
              <div>
                <p className="text-[9px] text-[color:var(--st-text-muted)] mb-1">Detected Packers</p>
                <div className="flex flex-wrap gap-1">
                  {scriptAnalysis.detectedPackers.map((p: string, i: number) => (
                    <span key={i} className="text-[9px] bg-purple-600/15 text-purple-400 border border-purple-500/20 rounded px-1.5 py-0.5">{p}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── Network Analysis ── */}
      {(networkAnalysis.totalRequests !== undefined || networkAnalysis.dgaSuspects?.length > 0) && (
        <Section title="Network Analysis" icon="&#127760;" accent="blue">
          <div className="space-y-2">
            <div className="flex flex-wrap gap-4">
              {networkAnalysis.totalRequests !== undefined && (
                <div className="text-center">
                  <p className="text-blue-400 text-sm font-semibold">{networkAnalysis.totalRequests}</p>
                  <p className="text-[9px] text-[color:var(--st-text-muted)]">Requests</p>
                </div>
              )}
              {networkAnalysis.externalDomains !== undefined && (
                <div className="text-center">
                  <p className="text-blue-400 text-sm font-semibold">{networkAnalysis.externalDomains}</p>
                  <p className="text-[9px] text-[color:var(--st-text-muted)]">Ext. Domains</p>
                </div>
              )}
              {networkAnalysis.beacons !== undefined && (
                <div className="text-center">
                  <p className={`text-sm font-semibold ${networkAnalysis.beacons > 0 ? 'text-orange-400' : 'text-blue-400'}`}>
                    {networkAnalysis.beacons}
                  </p>
                  <p className="text-[9px] text-[color:var(--st-text-muted)]">Beacons</p>
                </div>
              )}
            </div>
            {networkAnalysis.dgaSuspects?.length > 0 && (
              <div>
                <p className="text-[9px] text-[color:var(--st-text-muted)] mb-1">DGA Suspect Domains</p>
                <div className="space-y-0.5">
                  {networkAnalysis.dgaSuspects.map((d: string, i: number) => (
                    <p key={i} className="text-[10px] font-mono text-red-400 bg-red-600/10 rounded px-1.5 py-0.5 break-all">{d}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── ArtifactQL Findings ── */}
      {artifactqlFindings && artifactqlFindings.matches.length > 0 && (
        <Section title="Artifact Detections" icon="&#128270;" count={artifactqlFindings.matches.length} accent="purple">
          <div className="space-y-2">
            <div className="flex items-center gap-3 mb-2 text-[9px] text-[color:var(--st-text-muted)]">
              <span>{artifactqlFindings.artifactsEvaluated} artifacts evaluated</span>
              <span>{artifactqlFindings.totalTimeMs}ms</span>
            </div>
            {artifactqlFindings.matches.map((m: any, i: number) => (
              <div key={i} className={`rounded border ${getSevColor(m.severity).border} ${getSevColor(m.severity).bg} px-2 py-1.5`}>
                <div className="flex items-center gap-2 mb-0.5">
                  <SeverityPill severity={m.severity} />
                  <span className="text-[10px] text-[color:var(--st-text-primary)] font-medium">{m.artifactName}</span>
                  {m.mitre && (
                    <span className="text-[8px] text-purple-400 bg-purple-600/15 rounded px-1 py-0.5">{m.mitre}</span>
                  )}
                  <span className="text-[9px] text-[color:var(--st-text-muted)] ml-auto">{m.matchCount} match{m.matchCount !== 1 ? 'es' : ''}</span>
                </div>
                <p className="text-[9px] text-[color:var(--st-text-muted)] font-mono mb-1 break-all">{m.matchedQuery}</p>
                {m.evidenceRows && m.evidenceRows.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {m.evidenceRows.slice(0, 3).map((row: any, j: number) => (
                      <div key={j} className="text-[9px] text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-panel)] rounded px-1.5 py-0.5 font-mono break-all truncate">
                        {Object.entries(row).filter(([, v]) => v !== null).slice(0, 4).map(([k, v]) => `${k}=${String(v).slice(0, 40)}`).join(' | ')}
                      </div>
                    ))}
                    {m.evidenceRows.length > 3 && (
                      <p className="text-[8px] text-[color:var(--st-text-muted)]">+{m.evidenceRows.length - 3} more rows</p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Advanced Findings ── */}
      {advancedFindings.length > 0 && (
        <Section title="Advanced Findings" icon="&#128300;" count={advancedFindings.length} defaultOpen={false}>
          <div className="space-y-2">
            {advancedBySource.map(([source, findings]) => {
              const sourceColor = source.includes('dns') ? 'blue' : 'purple';
              const sourceLabel = source.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
              return (
                <div key={source}>
                  <p className={`text-[10px] text-${sourceColor}-400 font-medium mb-1`}>{sourceLabel}</p>
                  <div className="space-y-1">
                    {findings.map((f, i) => (
                      <div key={i} className={`rounded border ${getSevColor(f.severity).border} ${getSevColor(f.severity).bg} px-2 py-1.5`}>
                        <div className="flex items-center gap-2 mb-0.5">
                          <SeverityPill severity={f.severity} />
                          <span className="text-[9px] text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-elevated)] rounded px-1 py-0.5">{f.category}</span>
                          {f.mitre && (
                            <span className="text-[8px] text-purple-400 bg-purple-600/15 rounded px-1 py-0.5">{f.mitre}</span>
                          )}
                        </div>
                        <p className="text-[10px] text-[color:var(--st-text-secondary)]">{f.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Graph View — MISP/Maltego-style SVG
// ═══════════════════════════════════════════════════════════════

function buildGraph(details: Record<string, any>): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const W = 800, H = 600;
  const centerX = W / 2, centerY = H / 2;

  // Target node (center)
  const targetLabel = details.pageUrl
    ? new URL(details.pageUrl).hostname
    : 'Target';
  nodes.push({ id: 'target', label: targetLabel, type: 'target', x: centerX, y: centerY });

  const categories: { key: string; label: string; angle: number; items: any[] }[] = [];

  // Signatures
  const sigs: Signature[] = details.signatures || [];
  if (sigs.length > 0) categories.push({ key: 'sigs', label: 'Signatures', angle: Math.PI * 1.25, items: sigs });

  // Network
  const net = details.networkAnalysis || {};
  const netItems: any[] = [];
  if ((net.dgaSuspects || []).length > 0) net.dgaSuspects.forEach((d: string) => netItems.push({ type: 'dga', label: d, severity: 'high' }));
  if (net.beacons > 0) netItems.push({ type: 'beacon', label: `${net.beacons} beacon(s)`, severity: 'medium' });
  if (netItems.length > 0) categories.push({ key: 'net', label: 'Network', angle: Math.PI * 0.75, items: netItems });

  // Script
  const scr = details.scriptAnalysis || {};
  const scrItems: any[] = [];
  if (scr.obfuscationScore > 30) scrItems.push({ type: 'obfuscation', label: `Obfuscation: ${scr.obfuscationScore}`, severity: scr.obfuscationScore > 70 ? 'high' : 'medium' });
  if (scr.evalCount > 0) scrItems.push({ type: 'eval', label: `${scr.evalCount} eval()`, severity: 'medium' });
  if ((scr.detectedPackers || []).length > 0) scrItems.push({ type: 'packer', label: scr.detectedPackers.join(', '), severity: 'high' });
  if (scrItems.length > 0) categories.push({ key: 'scr', label: 'Script', angle: Math.PI * 1.75, items: scrItems });

  // Advanced
  const adv: AdvancedFinding[] = details.advancedFindings || [];
  if (adv.length > 0) categories.push({ key: 'adv', label: 'Advanced', angle: Math.PI * 0.25, items: adv });

  // ArtifactQL
  const aqlMatches = (details.artifactqlFindings as any)?.matches || [];
  if (aqlMatches.length > 0) {
    const aqlItems = aqlMatches.map((m: any) => ({
      ...m,
      description: m.artifactName,
      source: 'artifactql',
      category: 'artifactql',
    }));
    categories.push({ key: 'aql', label: 'Artifacts', angle: Math.PI * 0.5, items: aqlItems });
  }

  const R1 = 140; // category ring distance
  const R2 = 260; // item ring distance

  // Collect all MITRE IDs for dedup
  const mitreNodes = new Map<string, { x: number; y: number }>();

  categories.forEach((cat, ci) => {
    const catX = centerX + R1 * Math.cos(cat.angle);
    const catY = centerY + R1 * Math.sin(cat.angle);
    const catNodeId = `cat-${cat.key}`;
    nodes.push({ id: catNodeId, label: cat.label, type: 'category', x: catX, y: catY });
    edges.push({ from: 'target', to: catNodeId, type: 'primary' });

    // Cluster check — if >5 signatures of same severity, collapse
    if (cat.key === 'sigs') {
      const sevGroups: Record<string, Signature[]> = {};
      for (const s of cat.items as Signature[]) {
        (sevGroups[s.severity] ||= []).push(s);
      }
      let itemIdx = 0;
      Object.entries(sevGroups).forEach(([sev, group]) => {
        if (group.length > 5) {
          // Cluster node
          const angle = cat.angle + ((itemIdx / Math.max(1, Object.keys(sevGroups).length - 1)) - 0.5) * 0.8;
          const ix = centerX + R2 * Math.cos(angle);
          const iy = centerY + R2 * Math.sin(angle);
          const clusterId = `cluster-${sev}`;
          nodes.push({ id: clusterId, label: `${group.length} ${sev}`, type: 'cluster', severity: sev, x: ix, y: iy, count: group.length });
          edges.push({ from: catNodeId, to: clusterId, type: 'secondary', severity: sev });

          // Collect MITRE from cluster
          for (const s of group) {
            if (s.mitre && !mitreNodes.has(s.mitre)) {
              mitreNodes.set(s.mitre, { x: 0, y: 0 }); // position later
            }
            if (s.mitre) {
              edges.push({ from: clusterId, to: `mitre-${s.mitre}`, type: 'mitre' });
            }
          }
          itemIdx++;
        } else {
          // Individual nodes
          group.forEach((s, si) => {
            const totalItems = cat.items.length <= 5 ? cat.items.length : Object.keys(sevGroups).length;
            const spread = Math.min(1.2, 0.3 * totalItems);
            const angle = cat.angle + ((itemIdx / Math.max(1, totalItems - 1)) - 0.5) * spread;
            const ix = centerX + R2 * Math.cos(angle);
            const iy = centerY + R2 * Math.sin(angle);
            const nodeId = `sig-${s.id}`;
            nodes.push({ id: nodeId, label: s.name, type: 'signature', severity: s.severity, x: ix, y: iy, detail: s.evidence.join('; ') });
            edges.push({ from: catNodeId, to: nodeId, type: 'secondary', severity: s.severity });
            if (s.mitre) {
              if (!mitreNodes.has(s.mitre)) mitreNodes.set(s.mitre, { x: 0, y: 0 });
              edges.push({ from: nodeId, to: `mitre-${s.mitre}`, type: 'mitre' });
            }
            itemIdx++;
          });
        }
      });
    } else {
      // Other categories — place items around their category
      cat.items.forEach((item, ii) => {
        const spread = Math.min(1.0, 0.3 * cat.items.length);
        const angle = cat.angle + ((ii / Math.max(1, cat.items.length - 1)) - 0.5) * spread;
        const ix = centerX + R2 * Math.cos(angle);
        const iy = centerY + R2 * Math.sin(angle);
        let nodeId: string, label: string, type: GraphNode['type'], severity: string | undefined, source: string | undefined;

        if (cat.key === 'net') {
          nodeId = `net-${ii}`;
          label = item.label;
          type = 'network';
          severity = item.severity;
        } else if (cat.key === 'scr') {
          nodeId = `scr-${ii}`;
          label = item.label;
          type = 'script';
          severity = item.severity;
        } else {
          // advanced
          const af = item as AdvancedFinding;
          nodeId = `adv-${ii}`;
          label = af.description.length > 40 ? af.description.slice(0, 37) + '...' : af.description;
          type = 'advanced';
          severity = af.severity;
          source = af.source;
          if (af.mitre) {
            if (!mitreNodes.has(af.mitre)) mitreNodes.set(af.mitre, { x: 0, y: 0 });
            edges.push({ from: nodeId, to: `mitre-${af.mitre}`, type: 'mitre' });
          }
        }
        nodes.push({ id: nodeId, label, type, severity, source, x: ix, y: iy });
        edges.push({ from: catNodeId, to: nodeId, type: 'secondary', severity });
      });
    }
  });

  // Place MITRE nodes on the right side
  const mitreList = Array.from(mitreNodes.keys());
  const mitreStartY = centerY - (mitreList.length - 1) * 25;
  mitreList.forEach((mid, i) => {
    const mx = W - 80;
    const my = Math.max(30, mitreStartY + i * 50);
    mitreNodes.set(mid, { x: mx, y: my });
    nodes.push({ id: `mitre-${mid}`, label: mid, type: 'mitre', x: mx, y: my });
  });

  return { nodes, edges };
}

// SVG shape renderers
function NodeShape({ node, hovered, onClick, onMouseEnter, onMouseLeave }: {
  node: GraphNode;
  hovered: boolean;
  onClick: () => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}) {
  const sevHex = node.severity ? getSevColor(node.severity).hex : '#6b7280';
  const opacity = hovered ? 1 : 0.85;
  const strokeW = hovered ? 2.5 : 1.5;
  const labelFontSize = node.type === 'target' ? 11 : node.type === 'category' ? 10 : 8;
  const truncLabel = node.label.length > 22 ? node.label.slice(0, 19) + '...' : node.label;

  const commonProps = { onClick, onMouseEnter, onMouseLeave, style: { cursor: 'pointer' } };

  switch (node.type) {
    case 'target':
      return (
        <g {...commonProps} opacity={opacity}>
          <rect x={node.x - 55} y={node.y - 18} width={110} height={36} rx={8}
            fill="#0d1117" stroke="#3b82f6" strokeWidth={strokeW + 0.5} />
          <text x={node.x} y={node.y + 4} textAnchor="middle" fill="#93c5fd" fontSize={labelFontSize} fontWeight="600">{truncLabel}</text>
        </g>
      );
    case 'category':
      return (
        <g {...commonProps} opacity={opacity}>
          <rect x={node.x - 40} y={node.y - 14} width={80} height={28} rx={6}
            fill="#1e293b" stroke="#475569" strokeWidth={strokeW} />
          <text x={node.x} y={node.y + 4} textAnchor="middle" fill="#94a3b8" fontSize={labelFontSize} fontWeight="500">{node.label}</text>
        </g>
      );
    case 'mitre':
      // Hexagon
      const s = hovered ? 22 : 18;
      const hex = Array.from({ length: 6 }, (_, i) => {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        return `${node.x + s * Math.cos(a)},${node.y + s * Math.sin(a)}`;
      }).join(' ');
      return (
        <g {...commonProps} opacity={opacity}>
          <polygon points={hex} fill="#2e1065" stroke="#a855f7" strokeWidth={strokeW} />
          <text x={node.x} y={node.y + 3} textAnchor="middle" fill="#c084fc" fontSize={8} fontWeight="600">{node.label}</text>
        </g>
      );
    case 'network':
      // Diamond
      const ds = hovered ? 18 : 14;
      const diamond = `${node.x},${node.y - ds} ${node.x + ds},${node.y} ${node.x},${node.y + ds} ${node.x - ds},${node.y}`;
      return (
        <g {...commonProps} opacity={opacity}>
          <polygon points={diamond} fill="#0d1117" stroke={sevHex} strokeWidth={strokeW} />
          <text x={node.x} y={node.y + 3} textAnchor="middle" fill={sevHex} fontSize={7}>{truncLabel}</text>
        </g>
      );
    case 'script':
      // Circle
      const r = hovered ? 20 : 16;
      return (
        <g {...commonProps} opacity={opacity}>
          <circle cx={node.x} cy={node.y} r={r} fill="#0d1117" stroke="#a855f7" strokeWidth={strokeW} />
          <text x={node.x} y={node.y + 3} textAnchor="middle" fill="#c084fc" fontSize={7}>{truncLabel}</text>
        </g>
      );
    case 'cluster':
      return (
        <g {...commonProps} opacity={opacity}>
          <rect x={node.x - 36} y={node.y - 14} width={72} height={28} rx={6}
            fill="#0d1117" stroke={sevHex} strokeWidth={strokeW} strokeDasharray="4 2" />
          <text x={node.x} y={node.y + 4} textAnchor="middle" fill={sevHex} fontSize={9} fontWeight="500">{truncLabel}</text>
        </g>
      );
    default:
      // signature / advanced — rounded rect
      const w = hovered ? 110 : 90;
      const h = 24;
      const borderColor = node.source?.includes('dns') ? '#3b82f6' : node.source?.includes('heap') ? '#a855f7' : sevHex;
      return (
        <g {...commonProps} opacity={opacity}>
          <rect x={node.x - w / 2} y={node.y - h / 2} width={w} height={h} rx={5}
            fill="#0d1117" stroke={borderColor} strokeWidth={strokeW} />
          <text x={node.x} y={node.y + 3} textAnchor="middle" fill={borderColor} fontSize={7}>{truncLabel}</text>
        </g>
      );
  }
}

function GraphView({ details }: { details: Record<string, any> }) {
  const { nodes, edges } = useMemo(() => buildGraph(details), [details]);
  const [hovered, setHovered] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [scale, setScale] = useState(1);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setScale(s => Math.max(0.4, Math.min(2, s - e.deltaY * 0.001)));
  }, []);

  // Build adjacency for highlighting
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    for (const e of edges) {
      if (!adj.has(e.from)) adj.set(e.from, new Set());
      if (!adj.has(e.to)) adj.set(e.to, new Set());
      adj.get(e.from)!.add(e.to);
      adj.get(e.to)!.add(e.from);
    }
    return adj;
  }, [edges]);

  const isHighlighted = (nodeId: string) => {
    if (!hovered) return true;
    if (nodeId === hovered) return true;
    return adjacency.get(hovered)?.has(nodeId) || false;
  };

  const isEdgeHighlighted = (from: string, to: string) => {
    if (!hovered) return true;
    return hovered === from || hovered === to;
  };

  const selectedNode = selected ? nodes.find(n => n.id === selected) : null;

  if (nodes.length <= 1) {
    return <p className="text-[color:var(--st-text-muted)] text-center text-[11px] py-4">No findings to visualize</p>;
  }

  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-[color:var(--st-border)] bg-[color:var(--st-bg-base)] overflow-hidden" onWheel={handleWheel}>
        <svg
          ref={svgRef}
          viewBox="0 0 800 600"
          className="w-full"
          style={{ minHeight: 300, maxHeight: 480, transform: `scale(${scale})`, transformOrigin: 'center center' }}
        >
          <defs>
            <marker id="arrow-purple" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="6" markerHeight="6" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#a855f7" />
            </marker>
          </defs>

          {/* Edges */}
          {edges.map((e, i) => {
            const fromNode = nodes.find(n => n.id === e.from);
            const toNode = nodes.find(n => n.id === e.to);
            if (!fromNode || !toNode) return null;
            const highlighted = isEdgeHighlighted(e.from, e.to);
            const sevHex = e.severity ? getSevColor(e.severity).hex : '#334155';
            const strokeColor = e.type === 'mitre' ? '#a855f7' : e.type === 'primary' ? '#475569' : sevHex;
            return (
              <line
                key={i}
                x1={fromNode.x} y1={fromNode.y}
                x2={toNode.x} y2={toNode.y}
                stroke={strokeColor}
                strokeWidth={e.type === 'primary' ? 2 : 1}
                strokeDasharray={e.type === 'mitre' ? '5 3' : undefined}
                markerEnd={e.type === 'mitre' ? 'url(#arrow-purple)' : undefined}
                opacity={highlighted ? 0.7 : 0.15}
              >
                {e.type === 'mitre' && (
                  <animate attributeName="stroke-dashoffset" from="16" to="0" dur="1.5s" repeatCount="indefinite" />
                )}
              </line>
            );
          })}

          {/* Nodes */}
          {nodes.map(node => (
            <NodeShape
              key={node.id}
              node={node}
              hovered={hovered === node.id}
              onClick={() => setSelected(selected === node.id ? null : node.id)}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
            />
          ))}

          {/* Tooltip on hover */}
          {hovered && (() => {
            const n = nodes.find(nd => nd.id === hovered);
            if (!n) return null;
            const tooltipW = 180;
            const tx = Math.min(n.x + 15, 800 - tooltipW - 5);
            const ty = Math.max(n.y - 30, 5);
            return (
              <g pointerEvents="none">
                <rect x={tx} y={ty} width={tooltipW} height={40} rx={4} fill="#1e293b" stroke="#334155" strokeWidth={1} opacity={0.95} />
                <text x={tx + 8} y={ty + 15} fill="#e2e8f0" fontSize={9} fontWeight="500">
                  {n.label.slice(0, 30)}
                </text>
                <text x={tx + 8} y={ty + 28} fill="#6b7280" fontSize={8}>
                  {n.type}{n.severity ? ` | ${n.severity}` : ''}{n.count ? ` | ${n.count} items` : ''}
                </text>
              </g>
            );
          })()}
        </svg>
      </div>

      {/* Detail panel below graph */}
      {selectedNode && (
        <div className="rounded-lg border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)] p-3">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[color:var(--st-text-secondary)] text-[11px] font-medium">{selectedNode.label}</span>
            {selectedNode.severity && <SeverityPill severity={selectedNode.severity} />}
            <span className="text-[9px] text-[color:var(--st-text-muted)] capitalize">{selectedNode.type}</span>
          </div>
          {selectedNode.detail && (
            <p className="text-[10px] text-[color:var(--st-text-muted)] font-mono break-all">{selectedNode.detail}</p>
          )}
          {selectedNode.count && (
            <p className="text-[10px] text-[color:var(--st-text-muted)]">{selectedNode.count} findings in this cluster</p>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// Main Component — Tab switcher
// ═══════════════════════════════════════════════════════════════

export function SandboxResultView({ details, verdict, score }: SandboxResultViewProps) {
  const [view, setView] = useState<'report' | 'graph'>('report');

  return (
    <div className="mt-2 pt-2 border-t border-[color:var(--st-border)]">
      {/* Tab bar */}
      <div className="flex items-center gap-1 mb-2">
        <button
          onClick={() => setView('report')}
          className={`text-[10px] px-2 py-1 rounded transition-colors ${
            view === 'report'
              ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
              : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-muted)] border border-transparent'
          }`}
        >
          Report
        </button>
        <button
          onClick={() => setView('graph')}
          className={`text-[10px] px-2 py-1 rounded transition-colors ${
            view === 'graph'
              ? 'bg-purple-600/20 text-purple-400 border border-purple-500/30'
              : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-muted)] border border-transparent'
          }`}
        >
          Graph
        </button>
      </div>

      {view === 'report'
        ? <ReportView details={details} verdict={verdict} score={score} />
        : <GraphView details={details} />
      }
    </div>
  );
}

export default SandboxResultView;
