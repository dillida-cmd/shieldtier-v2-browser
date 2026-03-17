// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Graph Tab (SVG entity relationship diagram)
// ---------------------------------------------------------------------------

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import type { Severity, GraphNode, LogGraph, LogVerdict, NodePos } from './log-analysis-types';
import {
  NODE_COLORS,
  SEVERITY_LEVELS,
  SEVERITY_INDEX,
  ENTITY_TYPES,
  SEV_BUTTON_STYLES,
  getSeverityBadge,
  getPhaseColor,
  pickDefaultSeverity,
  layoutNodes,
} from './log-analysis-utils';
import { EmptySection } from './EmptySection';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';

export function GraphTab({
  graph,
  selectedNode,
  onSelectNode,
  verdict,
}: {
  graph: LogGraph;
  selectedNode: string | null;
  onSelectNode: (id: string | null) => void;
  verdict: LogVerdict | null;
}) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const svgContainerRef = useRef<HTMLDivElement>(null);
  // Classify process nodes into process (parent) vs subprocess (child spawned by another process)
  const classifiedNodes = useMemo(() => {
    if (graph.nodes.length === 0) return [];
    const spawnedTargets = new Set<string>();
    const spawnSources = new Set<string>();
    for (const e of graph.edges) {
      if (e.label === 'spawned') {
        spawnedTargets.add(e.target);
        spawnSources.add(e.source);
      }
    }
    return graph.nodes.map(n => {
      if (n.type !== 'process') return n;
      const isSpawnedChild = spawnedTargets.has(n.id);
      const isParent = spawnSources.has(n.id);
      if (isSpawnedChild && !isParent) {
        return { ...n, type: 'subprocess' as const };
      }
      return n;
    });
  }, [graph.nodes, graph.edges]);

  // --- Filter state ---
  const [sevThreshold, setSevThreshold] = useState<Severity>(() => pickDefaultSeverity(graph.nodes));
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(() => new Set());

  // Reset filters when graph changes
  const graphRef = useRef(graph);
  useEffect(() => {
    if (graphRef.current !== graph) {
      graphRef.current = graph;
      setSevThreshold(pickDefaultSeverity(graph.nodes));
      setHiddenTypes(new Set());
      onSelectNode(null);
    }
  }, [graph, onSelectNode]);

  // --- Compute visible nodes ---
  // 1. Find "primary" nodes that pass severity threshold
  // 2. Include their direct neighbors (context nodes) so the graph stays connected
  const { visibleNodes, visibleEdges, filteredCount } = useMemo(() => {
    const threshIdx = SEVERITY_INDEX[sevThreshold] ?? 0;

    // Step 1: primary nodes = pass severity AND type not hidden
    const primaryIds = new Set<string>();
    for (const n of classifiedNodes) {
      if (hiddenTypes.has(n.type)) continue;
      const nIdx = SEVERITY_INDEX[n.severity || 'info'] ?? 0;
      if (nIdx >= threshIdx) primaryIds.add(n.id);
    }

    // Step 2: context nodes = direct neighbors of primary nodes (keeps graph connected)
    // Always include hosts and users as bridge nodes
    const contextIds = new Set<string>(primaryIds);
    for (const edge of graph.edges) {
      const srcPrimary = primaryIds.has(edge.source);
      const tgtPrimary = primaryIds.has(edge.target);
      if (srcPrimary || tgtPrimary) {
        // Add the neighbor, but respect type toggles
        if (srcPrimary) {
          const tgtNode = classifiedNodes.find(n => n.id === edge.target);
          if (tgtNode && !hiddenTypes.has(tgtNode.type)) contextIds.add(edge.target);
        }
        if (tgtPrimary) {
          const srcNode = classifiedNodes.find(n => n.id === edge.source);
          if (srcNode && !hiddenTypes.has(srcNode.type)) contextIds.add(edge.source);
        }
      }
    }

    const vNodes = classifiedNodes.filter(n => contextIds.has(n.id));
    const vEdges = graph.edges.filter(e => contextIds.has(e.source) && contextIds.has(e.target));
    const filtered = classifiedNodes.length - vNodes.length;

    return { visibleNodes: vNodes, visibleEdges: vEdges, filteredCount: filtered };
  }, [classifiedNodes, graph.edges, sevThreshold, hiddenTypes]);

  // Layout from visible nodes
  const layout = useMemo(() => {
    if (visibleNodes.length === 0) return null;
    return layoutNodes(visibleNodes);
  }, [visibleNodes]);

  const posMap = useMemo(() => {
    const m = new Map<string, NodePos>();
    if (layout) for (const p of layout.positions) m.set(p.id, p);
    return m;
  }, [layout]);

  // Highlighted edges
  const highlightedEdges = useMemo(() => {
    if (!selectedNode) return null;
    const set = new Set<number>();
    visibleEdges.forEach((e, i) => {
      if (e.source === selectedNode || e.target === selectedNode) set.add(i);
    });
    return set;
  }, [selectedNode, visibleEdges]);

  // Toggle entity type
  const toggleType = useCallback((type: string) => {
    setHiddenTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  if (classifiedNodes.length === 0) {
    return <EmptySection message="No entities to visualize" />;
  }

  const W = layout ? layout.width : 600;
  const H = layout ? layout.height : 400;

  return (
    <div className="space-y-2">
      {/* Severity threshold */}
      <div className="flex items-center gap-2 text-[10px]">
        <span className="text-[color:var(--st-text-muted)] font-medium uppercase tracking-wider">Severity</span>
        {SEVERITY_LEVELS.map(sev => {
          const isActive = sev === sevThreshold;
          const style = SEV_BUTTON_STYLES[sev];
          const count = classifiedNodes.filter(n => (n.severity || 'info') === sev).length;
          return (
            <Button
              key={sev}
              variant="outline"
              size="sm"
              onClick={() => setSevThreshold(sev)}
              className={cn(
                'px-2 py-0.5 h-auto text-[10px] font-medium capitalize',
                isActive ? style.active : style.inactive
              )}
            >
              {sev}{isActive ? '+' : ''}{count > 0 ? ` (${count})` : ''}
            </Button>
          );
        })}
        {filteredCount > 0 && (
          <span className="text-[color:var(--st-text-muted)] ml-1 font-mono">
            ({filteredCount} hidden)
          </span>
        )}
      </div>

      {/* Entity type toggles + legend */}
      <div className="flex items-center gap-3 text-[10px]">
        <span className="text-[color:var(--st-text-muted)] font-medium uppercase tracking-wider">Show</span>
        {ENTITY_TYPES.map(type => {
          const c = NODE_COLORS[type];
          const isOn = !hiddenTypes.has(type);
          const count = classifiedNodes.filter(n => n.type === type).length;
          if (count === 0) return null;
          return (
            <Button
              key={type}
              variant="ghost"
              size="sm"
              onClick={() => toggleType(type)}
              className={cn(
                'flex items-center gap-1 px-1.5 py-0.5 h-auto text-[10px]',
                isOn ? 'opacity-100' : 'opacity-30'
              )}
            >
              {type === 'host' || type === 'process' || type === 'subprocess' || type === 'file' ? (
                <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: c.fill }} />
              ) : (
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: c.fill }} />
              )}
              <span className={cn('capitalize', isOn ? 'text-[color:var(--st-text-secondary)]' : 'text-[color:var(--st-text-muted)]')}>
                {type} ({count})
              </span>
            </Button>
          );
        })}
        <div className="ml-auto flex items-center gap-2">
          {selectedNode && (
            <Button
              variant="link"
              size="sm"
              onClick={() => onSelectNode(null)}
              className="text-blue-400 hover:text-blue-300 h-auto px-0 text-[10px]"
            >
              Clear selection
            </Button>
          )}
        </div>
      </div>

      {/* SVG */}
      {visibleNodes.length === 0 ? (
        <div className="flex items-center justify-center h-48 text-[color:var(--st-text-muted)] text-xs">
          No nodes match current filters — try lowering the severity threshold
        </div>
      ) : (
        <div ref={svgContainerRef} className="rounded-lg glass-light border overflow-auto relative">
          <svg
            viewBox={`0 0 ${W} ${H}`}
            className="w-full"
            style={{ minHeight: 400 }}
            onClick={() => onSelectNode(null)}
          >
            {/* Column headers */}
            {layout!.columns.map(col => (
              <text
                key={`col-${col.type}`}
                x={col.x}
                y={18}
                textAnchor="middle"
                fill="var(--st-text-muted)"
                fontSize="11"
                fontFamily="sans-serif"
                fontWeight="600"
                letterSpacing="0.08em"
              >
                {col.type.toUpperCase()}
              </text>
            ))}

            {/* Column separators */}
            {layout!.columns.map((col, i) => {
              if (i === 0) return null;
              const prevX = layout!.columns[i - 1].x;
              const midX = (prevX + col.x) / 2;
              return (
                <line
                  key={`sep-${i}`}
                  x1={midX} y1={30}
                  x2={midX} y2={H - 10}
                  stroke="var(--st-border)"
                  strokeWidth={1}
                  strokeDasharray="4 4"
                  opacity={0.4}
                />
              );
            })}

            {/* Edges */}
            {visibleEdges.map((edge, i) => {
              const src = posMap.get(edge.source);
              const tgt = posMap.get(edge.target);
              if (!src || !tgt) return null;

              const isHighlighted = highlightedEdges !== null && highlightedEdges.has(i);
              const showLabel = isHighlighted;

              // Severity-aware edge styling
              const edgeSevColor = edge.severity === 'critical' ? '#ef4444' :
                                   edge.severity === 'high' ? '#f97316' :
                                   edge.severity === 'medium' ? '#eab308' :
                                   '#475569';
              const edgeSevWidth = (edge.severity === 'critical' || edge.severity === 'high') ? 2.5 :
                                   edge.severity === 'medium' ? 1.5 : 0.8;
              const edgeDash = (!edge.severity || edge.severity === 'info' || edge.severity === 'low')
                               ? '4 4' : 'none';

              const opacity = highlightedEdges !== null
                ? (isHighlighted ? 0.9 : 0.04)
                : (edge.severity === 'critical' || edge.severity === 'high') ? 0.6
                : edge.severity === 'medium' ? 0.3
                : 0.15;

              const dx = (tgt.x - src.x) * 0.5;
              const path = `M ${src.x} ${src.y} C ${src.x + dx} ${src.y}, ${tgt.x - dx} ${tgt.y}, ${tgt.x} ${tgt.y}`;

              const mx = (src.x + tgt.x) / 2;
              const my = (src.y + tgt.y) / 2;

              return (
                <g key={`edge-${i}`}>
                  <path
                    d={path}
                    fill="none"
                    stroke={isHighlighted ? '#60a5fa' : edgeSevColor}
                    strokeWidth={isHighlighted ? 2 : edgeSevWidth}
                    strokeDasharray={isHighlighted ? 'none' : edgeDash}
                    opacity={opacity}
                  />
                  {showLabel && (
                    <g>
                      <rect
                        x={mx - 40} y={my - 10}
                        width={80} height={16}
                        rx={3}
                        fill="var(--st-bg-base)"
                        opacity={0.9}
                      />
                      <text
                        x={mx} y={my + 2}
                        textAnchor="middle"
                        fill="#93c5fd"
                        fontSize="9"
                        fontFamily="sans-serif"
                      >
                        {edge.label}{edge.count > 1 ? ` (${edge.count})` : ''}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {layout!.positions.map(node => {
              const colors = NODE_COLORS[node.type] || NODE_COLORS.process;
              const isSelected = selectedNode === node.id;
              const isConnected = selectedNode !== null &&
                visibleEdges.some(e =>
                  (e.source === selectedNode && e.target === node.id) ||
                  (e.target === selectedNode && e.source === node.id)
                );
              const dimmed = selectedNode !== null && !isSelected && !isConnected;
              const nodeOpacity = dimmed ? 0.15 : 1;
              const isRect = node.type === 'host' || node.type === 'process' || node.type === 'subprocess' || node.type === 'file';
              const sevBadge = node.severity === 'critical' || node.severity === 'high' ? node.severity : null;

              return (
                <g
                  key={node.id}
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectNode(isSelected ? null : node.id);
                  }}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  style={{ cursor: 'pointer', opacity: nodeOpacity }}
                >
                  {/* Glow effect for selected/connected nodes */}
                  {(isSelected || isConnected) && (
                    isRect ? (
                      <rect
                        x={node.x - 22} y={node.y - 22}
                        width={44} height={44}
                        rx={6}
                        fill="none"
                        stroke={isSelected ? '#fff' : colors.stroke}
                        strokeWidth={1}
                        opacity={0.3}
                      />
                    ) : (
                      <circle
                        cx={node.x} cy={node.y} r={22}
                        fill="none"
                        stroke={isSelected ? '#fff' : colors.stroke}
                        strokeWidth={1}
                        opacity={0.3}
                      />
                    )
                  )}
                  {isRect ? (
                    <rect
                      x={node.x - 16} y={node.y - 16}
                      width={32} height={32}
                      rx={4}
                      fill={colors.fill}
                      stroke={isSelected ? '#fff' : colors.stroke}
                      strokeWidth={isSelected ? 2 : 1}
                      opacity={0.85}
                    />
                  ) : (
                    <circle
                      cx={node.x} cy={node.y} r={16}
                      fill={colors.fill}
                      stroke={isSelected ? '#fff' : colors.stroke}
                      strokeWidth={isSelected ? 2 : 1}
                      opacity={0.85}
                    />
                  )}
                  <text
                    x={node.x} y={node.y + 28}
                    textAnchor="middle"
                    fill={isSelected || isConnected ? '#e5e7eb' : '#9ca3af'}
                    fontSize="10"
                    fontFamily="monospace"
                  >
                    {node.label}
                  </text>

                  {/* MITRE tag below label for enriched nodes */}
                  {node.mitre && node.mitre.length > 0 && (
                    <text
                      x={node.x} y={node.y + 40}
                      textAnchor="middle"
                      fill="#a78bfa"
                      fontSize="8"
                      fontFamily="monospace"
                    >
                      {node.mitre.slice(0, 2).join(' ')}
                    </text>
                  )}

                  {/* Severity badge for high/critical nodes */}
                  {sevBadge && (
                    <g>
                      <circle
                        cx={node.x + 14} cy={node.y - 14}
                        r={6}
                        fill={sevBadge === 'critical' ? '#ef4444' : '#f97316'}
                        stroke="var(--st-bg-base)"
                        strokeWidth={1.5}
                      />
                      {sevBadge === 'critical' && (
                        <text
                          x={node.x + 14} y={node.y - 11}
                          textAnchor="middle"
                          fill="#fff"
                          fontSize="8"
                          fontWeight="bold"
                          fontFamily="sans-serif"
                        >!</text>
                      )}
                    </g>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Hover Info Card */}
          {hoveredNode && (() => {
            const hNode = posMap.get(hoveredNode);
            if (!hNode) return null;
            const edgeCount = visibleEdges.filter(e => e.source === hoveredNode || e.target === hoveredNode).length;
            const sevLabel = hNode.severity || 'info';

            return (
              <div
                className="absolute z-20 pointer-events-none"
                style={{
                  left: 12,
                  top: 12,
                }}
              >
                <div className="bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-lg shadow-xl p-3 min-w-[220px] max-w-[300px]">
                  {/* Header */}
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-xs text-[color:var(--st-text-primary)] font-mono font-bold truncate">{hNode.label}</span>
                    <Badge
                      size="sm"
                      className={cn('text-[9px] font-bold uppercase', getSeverityBadge(sevLabel as Severity))}
                    >
                      {sevLabel}
                    </Badge>
                  </div>
                  <div className="border-t border-[color:var(--st-border)] mb-1.5" />

                  {/* Reason */}
                  {hNode.reason && (
                    <div className="mb-1">
                      <span className="text-[9px] text-[color:var(--st-text-muted)] uppercase tracking-wider">Reason</span>
                      <p className="text-[10px] text-[color:var(--st-text-secondary)] leading-snug">{hNode.reason}</p>
                    </div>
                  )}

                  {/* MITRE */}
                  {hNode.mitre && hNode.mitre.length > 0 && (
                    <div className="mb-1">
                      <span className="text-[9px] text-[color:var(--st-text-muted)] uppercase tracking-wider">MITRE</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {hNode.mitre.map(m => (
                          <Badge key={m} size="sm" variant="purple" className="text-[9px] font-mono">
                            {m}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Stats row */}
                  <div className="flex items-center gap-3 mt-1">
                    {hNode.eventCount != null && (
                      <div>
                        <span className="text-[9px] text-[color:var(--st-text-muted)]">Events</span>
                        <p className="text-[11px] text-[color:var(--st-text-secondary)] font-bold font-mono">{hNode.eventCount}</p>
                      </div>
                    )}
                    <div>
                      <span className="text-[9px] text-[color:var(--st-text-muted)]">Edges</span>
                      <p className="text-[11px] text-[color:var(--st-text-secondary)] font-bold font-mono">{edgeCount}</p>
                    </div>
                    <div>
                      <span className="text-[9px] text-[color:var(--st-text-muted)]">Type</span>
                      <p className="text-[11px] text-[color:var(--st-text-secondary)] capitalize">{hNode.type}</p>
                    </div>
                  </div>

                  {/* Kill-chain phases */}
                  {hNode.phases && hNode.phases.length > 0 && (
                    <div className="mt-1.5">
                      <span className="text-[9px] text-[color:var(--st-text-muted)] uppercase tracking-wider">Phases</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {hNode.phases.map(p => (
                          <Badge
                            key={p}
                            size="sm"
                            variant="outline"
                            className={cn('rounded text-[9px]', getPhaseColor(p))}
                          >
                            {p.replace(/-/g, ' ')}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
