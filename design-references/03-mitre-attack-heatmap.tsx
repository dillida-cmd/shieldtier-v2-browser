/**
 * DESIGN REFERENCE ONLY — Do not import into the app.
 * Template: MITRE ATT&CK Heatmap
 * Target: src/renderer/src/components/MITREPanel.tsx
 * Source: 21st.dev Magic MCP Builder
 *
 * Key design patterns to extract:
 * - 14-column tactic grid (horizontally scrollable)
 * - Technique cells color-coded by severity
 * - Evidence count badges per technique
 * - Click-to-expand evidence tree overlay
 * - Sticky tactic headers
 * - Selected technique detail bar at bottom
 */

import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronRight, Shield, AlertTriangle, Info } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Evidence {
  id: string;
  description: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface Technique {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  evidenceCount: number;
  evidence: Evidence[];
}

interface Tactic {
  id: string;
  name: string;
  techniques: Technique[];
}

const cn = (...classes: Array<string | boolean | undefined | null>) => {
  return classes.filter(Boolean).join(' ');
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-900/80 hover:bg-red-800/80';
    case 'high': return 'bg-orange-800/80 hover:bg-orange-700/80';
    case 'medium': return 'bg-yellow-700/80 hover:bg-yellow-600/80';
    case 'low': return 'bg-blue-700/80 hover:bg-blue-600/80';
    default: return 'bg-slate-800/50 hover:bg-slate-700/50';
  }
};

const getSeverityBadgeColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-600 text-white';
    case 'high': return 'bg-orange-600 text-white';
    case 'medium': return 'bg-yellow-600 text-white';
    case 'low': return 'bg-blue-600 text-white';
    default: return 'bg-slate-600 text-white';
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case 'critical':
    case 'high': return <AlertTriangle className="w-3 h-3" />;
    case 'medium': return <Info className="w-3 h-3" />;
    case 'low': return <Shield className="w-3 h-3" />;
    default: return null;
  }
};

const generateSampleData = (): Tactic[] => {
  const tacticNames = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command & Control', 'Exfiltration', 'Impact',
    'Resource Development', 'Reconnaissance'
  ];
  const severities: Array<'critical' | 'high' | 'medium' | 'low' | 'none'> = ['critical', 'high', 'medium', 'low', 'none'];

  return tacticNames.map((name, tacticIdx) => ({
    id: `TA${String(tacticIdx + 1).padStart(4, '0')}`,
    name,
    techniques: Array.from({ length: Math.floor(Math.random() * 8) + 4 }, (_, techIdx) => {
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const evidenceCount = severity === 'none' ? 0 : Math.floor(Math.random() * 15) + 1;
      return {
        id: `T${String(tacticIdx * 100 + techIdx + 1).padStart(4, '0')}`,
        name: `Technique ${techIdx + 1}`,
        severity,
        evidenceCount,
        evidence: Array.from({ length: evidenceCount }, (_, evidIdx) => ({
          id: `E${String(evidIdx + 1).padStart(4, '0')}`,
          description: `Evidence item ${evidIdx + 1} for ${name}`,
          timestamp: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
          severity: severity === 'none' ? 'low' as const : severity
        }))
      };
    })
  }));
};

const MitreAttackHeatmap: React.FC<{ data?: Tactic[] }> = ({ data: propData }) => {
  const [expandedTechniques, setExpandedTechniques] = useState<Set<string>>(new Set());
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);
  const data = useMemo(() => propData || generateSampleData(), [propData]);

  const toggleTechnique = (techniqueId: string) => {
    setExpandedTechniques(prev => {
      const next = new Set(prev);
      if (next.has(techniqueId)) next.delete(techniqueId);
      else next.add(techniqueId);
      return next;
    });
  };

  const maxTechniques = Math.max(...data.map(t => t.techniques.length));

  return (
    <div className="w-full h-screen bg-[#1c1c1e] text-slate-200 p-4 overflow-hidden flex flex-col">
      {/* Header + Legend */}
      <div className="mb-4">
        <h1 className="text-2xl font-bold text-white mb-2">MITRE ATT&CK Heatmap</h1>
        <div className="flex gap-4 text-xs">
          <div className="flex items-center gap-2"><div className="w-4 h-4 bg-red-900/80 rounded" /><span>Critical</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 bg-orange-800/80 rounded" /><span>High</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 bg-yellow-700/80 rounded" /><span>Medium</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 bg-blue-700/80 rounded" /><span>Low</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 bg-slate-800/50 rounded" /><span>None</span></div>
        </div>
      </div>

      {/* Heatmap Grid */}
      <ScrollArea className="flex-1">
        <div className="inline-block min-w-full">
          <div className="grid gap-0.5" style={{ gridTemplateColumns: `repeat(${data.length}, minmax(140px, 1fr))` }}>
            {/* Tactic Headers */}
            {data.map(tactic => (
              <div key={tactic.id} className="bg-slate-800/80 p-2 border-b-2 border-slate-700 sticky top-0 z-10">
                <div className="font-mono text-xs text-slate-400 mb-1">{tactic.id}</div>
                <div className="font-semibold text-sm text-white leading-tight">{tactic.name}</div>
              </div>
            ))}

            {/* Technique Cells */}
            {Array.from({ length: maxTechniques }).map((_, rowIdx) => (
              <React.Fragment key={rowIdx}>
                {data.map(tactic => {
                  const technique = tactic.techniques[rowIdx];
                  if (!technique) return <div key={`${tactic.id}-${rowIdx}`} className="bg-slate-900/30 min-h-[80px]" />;
                  const isExpanded = expandedTechniques.has(technique.id);

                  return (
                    <div key={technique.id} className="relative">
                      <button
                        onClick={() => { toggleTechnique(technique.id); setSelectedTechnique(technique); }}
                        className={cn(
                          'w-full p-2 text-left transition-all duration-200 min-h-[80px] flex flex-col justify-between',
                          getSeverityColor(technique.severity),
                          'border border-slate-700/50 hover:border-slate-600'
                        )}
                      >
                        <div>
                          <div className="flex items-start justify-between gap-1 mb-1">
                            <span className="font-mono text-xs text-slate-300">{technique.id}</span>
                            {technique.evidenceCount > 0 && (
                              <Badge className={cn('text-[10px] px-1.5 py-0 h-4', getSeverityBadgeColor(technique.severity))}>
                                {technique.evidenceCount}
                              </Badge>
                            )}
                          </div>
                          <div className="text-xs text-slate-100 leading-tight line-clamp-2">{technique.name}</div>
                        </div>
                        {technique.evidenceCount > 0 && (
                          <div className="flex items-center gap-1 mt-2 text-[10px] text-slate-400">
                            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                            <span>{isExpanded ? 'Hide' : 'Show'} evidence</span>
                          </div>
                        )}
                      </button>

                      {/* Evidence Overlay */}
                      {isExpanded && technique.evidence.length > 0 && (
                        <div className="absolute left-0 right-0 top-full z-20 bg-slate-800 border border-slate-700 shadow-xl max-h-64 overflow-y-auto">
                          <div className="p-3">
                            <div className="text-xs font-semibold text-white mb-2 flex items-center gap-2">
                              <span className="font-mono">{technique.id}</span>
                              <span>Evidence ({technique.evidence.length})</span>
                            </div>
                            <div className="space-y-2">
                              {technique.evidence.map(evidence => (
                                <div key={evidence.id} className="bg-slate-900/50 p-2 rounded border border-slate-700/50">
                                  <div className="flex items-start gap-2 mb-1">
                                    <span className={cn('flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded', getSeverityBadgeColor(evidence.severity))}>
                                      {getSeverityIcon(evidence.severity)}
                                      {evidence.severity}
                                    </span>
                                    <span className="font-mono text-[10px] text-slate-400">{evidence.id}</span>
                                  </div>
                                  <div className="text-xs text-slate-300 mb-1">{evidence.description}</div>
                                  <div className="text-[10px] text-slate-500">{new Date(evidence.timestamp).toLocaleString()}</div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </React.Fragment>
            ))}
          </div>
        </div>
      </ScrollArea>

      {/* Selected Technique Detail Bar */}
      {selectedTechnique && (
        <div className="mt-4 bg-slate-800/80 p-4 rounded-lg border border-slate-700">
          <div className="flex items-start justify-between mb-2">
            <div>
              <span className="font-mono text-sm text-slate-400">{selectedTechnique.id}</span>
              <h3 className="text-lg font-semibold text-white">{selectedTechnique.name}</h3>
            </div>
            <Badge className={cn('text-xs', getSeverityBadgeColor(selectedTechnique.severity))}>
              {selectedTechnique.severity}
            </Badge>
          </div>
          <div className="text-sm text-slate-300">
            <span className="font-semibold">{selectedTechnique.evidenceCount}</span> evidence items detected
          </div>
        </div>
      )}
    </div>
  );
};

export default function MitreAttackHeatmapDemo() {
  return <MitreAttackHeatmap />;
}
