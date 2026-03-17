// ---------------------------------------------------------------------------
// ShieldTier Log Analysis Panel — Orchestrator
// ---------------------------------------------------------------------------
// Full log analysis UI: file open / drag-drop, analysis list, 7 sub-tabs
// (Overview, Events, Triage, Investigation, Graph, Verdict, Hunting).
// ---------------------------------------------------------------------------

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import type { LogAnalysisResult, SupportedFormat, SubTab } from './log-analysis-types';
import { EVENTS_PER_PAGE, getVerdictStyle } from './log-analysis-utils';
import { OverviewTab } from './OverviewTab';
import { EventsTab } from './EventsTab';
import { TriageTab } from './TriageTab';
import { InvestigationTab } from './InvestigationTab';
import { GraphTab } from './GraphTab';
import { VerdictTab } from './VerdictTab';
import { HuntingTab } from './HuntingTab';
import { EmptySection } from './EmptySection';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/tabs';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';

// ═══════════════════════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════════════════════

interface Props {
  session: { id: string; caseName?: string };
}

export default function LogAnalysisPanel({ session }: Props) {
  const [analyses, setAnalyses] = useState<LogAnalysisResult[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<SubTab>('overview');
  const [dragOver, setDragOver] = useState(false);
  const [eventSearch, setEventSearch] = useState('');
  const [eventSeverityFilter, setEventSeverityFilter] = useState<string | null>(null);
  const [eventPage, setEventPage] = useState(0);
  const [expandedEventIdx, setExpandedEventIdx] = useState<number | null>(null);
  const [formats, setFormats] = useState<SupportedFormat[]>([]);
  const [expandedChains, setExpandedChains] = useState<Set<number>>(new Set());
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null);

  const dropRef = useRef<HTMLDivElement>(null);

  const selected = useMemo(
    () => (selectedId ? analyses.find(a => a.id === selectedId) ?? null : null),
    [analyses, selectedId],
  );

  // -----------------------------------------------------------------------
  // Load existing results + listen for updates
  // -----------------------------------------------------------------------

  useEffect(() => {
    window.shieldtier.loganalysis.getResults(session.id).then((results: LogAnalysisResult[]) => {
      setAnalyses(results);
    });

    window.shieldtier.loganalysis.getFormats().then((fmts: SupportedFormat[]) => {
      setFormats(fmts);
    });

    const cleanupComplete = window.shieldtier.loganalysis.onComplete(
      (sid: string, result: LogAnalysisResult) => {
        if (sid === session.id) {
          setAnalyses(prev => {
            const idx = prev.findIndex(a => a.id === result.id);
            if (idx >= 0) {
              const next = [...prev];
              next[idx] = result;
              return next;
            }
            return [...prev, result];
          });
          setSelectedId(result.id);
        }
      },
    );

    const cleanupProgress = window.shieldtier.loganalysis.onProgress(
      (sid: string, progress: any) => {
        if (sid === session.id) {
          setAnalyses(prev => {
            const idx = prev.findIndex(a => a.id === progress.id);
            if (idx >= 0) {
              const next = [...prev];
              next[idx] = { ...next[idx], status: progress.status };
              return next;
            }
            return [
              ...prev,
              {
                id: progress.id,
                sessionId: session.id,
                fileName: progress.fileName || 'Analyzing...',
                format: 'unknown',
                eventCount: 0,
                parseErrors: 0,
                severityCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
                categoryCounts: {},
                events: [],
                insights: [],
                triage: null,
                investigation: null,
                graph: null,
                verdict: null,
                hunting: null,
                status: progress.status,
                startedAt: Date.now(),
              },
            ];
          });
          if (!selectedId) setSelectedId(progress.id);
        }
      },
    );

    return () => {
      cleanupComplete();
      cleanupProgress();
    };
  }, [session.id]);

  // -----------------------------------------------------------------------
  // File open handler
  // -----------------------------------------------------------------------

  const handleOpenFile = useCallback(async () => {
    await window.shieldtier.loganalysis.openFile(session.id);
  }, [session.id]);

  // -----------------------------------------------------------------------
  // Drag and drop
  // -----------------------------------------------------------------------

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);

      const files = e.dataTransfer?.files;
      if (!files || files.length === 0) return;
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        // The electron file object has a path property
        const filePath = (file as any).path;
        if (filePath) {
          await window.shieldtier.loganalysis.analyzeFile(session.id, filePath);
        }
      }
    },
    [session.id],
  );

  // -----------------------------------------------------------------------
  // Delete handler
  // -----------------------------------------------------------------------

  const handleDelete = useCallback(
    async (analysisId: string) => {
      await window.shieldtier.loganalysis.deleteResult(session.id, analysisId);
      setAnalyses(prev => prev.filter(a => a.id !== analysisId));
      if (selectedId === analysisId) {
        setSelectedId(null);
      }
    },
    [session.id, selectedId],
  );

  // -----------------------------------------------------------------------
  // Filtered events for Events tab
  // -----------------------------------------------------------------------

  const filteredEvents = useMemo(() => {
    if (!selected?.events) return [];
    let evts = selected.events;
    if (eventSeverityFilter) {
      evts = evts.filter(e => e.severity === eventSeverityFilter);
    }
    if (eventSearch.trim()) {
      const q = eventSearch.toLowerCase();
      evts = evts.filter(
        e =>
          e.message.toLowerCase().includes(q) ||
          e.eventType.toLowerCase().includes(q) ||
          e.category.toLowerCase().includes(q) ||
          e.raw.toLowerCase().includes(q),
      );
    }
    return evts;
  }, [selected, eventSeverityFilter, eventSearch]);

  const totalEventPages = Math.max(1, Math.ceil(filteredEvents.length / EVENTS_PER_PAGE));
  const pagedEvents = filteredEvents.slice(
    eventPage * EVENTS_PER_PAGE,
    (eventPage + 1) * EVENTS_PER_PAGE,
  );

  // Reset page when filters change
  useEffect(() => {
    setEventPage(0);
  }, [eventSearch, eventSeverityFilter, selectedId]);

  // Reset expanded chain state when switching analysis
  useEffect(() => {
    setExpandedChains(new Set());
    setExpandedEventIdx(null);
    setSelectedGraphNode(null);
  }, [selectedId]);

  // ═══════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════

  return (
    <div
      ref={dropRef}
      className="h-full flex flex-col overflow-hidden"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {dragOver && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-blue-500/5 border-2 border-dashed border-blue-500/40 rounded-lg pointer-events-none">
          <div className="text-center">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-blue-400 mx-auto mb-2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="12" y1="18" x2="12" y2="12" />
              <polyline points="9 15 12 12 15 15" />
            </svg>
            <p className="text-sm text-blue-400 font-medium">Drop log file to analyze</p>
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 glass-light border-b shrink-0">
        <Button
          onClick={handleOpenFile}
          variant="outline"
          size="sm"
          aria-label="Open log files for analysis"
          className="bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 border-blue-500/20"
        >
          Open Log Files...
        </Button>
        <div className="flex-1" />
        {formats.length > 0 && (
          <span className="text-[10px] text-[color:var(--st-text-muted)]" title={formats.map(f => f.name).join(', ')}>
            Supported: {formats.length} format{formats.length !== 1 ? 's' : ''}
          </span>
        )}
        <span className="text-[10px] text-[color:var(--st-text-muted)]">
          {analyses.length} {analyses.length === 1 ? 'analysis' : 'analyses'}
        </span>
      </div>

      {/* Empty state */}
      {analyses.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center max-w-sm">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[color:var(--st-text-muted)] mx-auto mb-4">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            <p className="text-sm text-[color:var(--st-text-muted)] mb-1">
              Drop a log file here or click Open Log File to start analyzing
            </p>
            {formats.length > 0 && (
              <p className="text-[11px] text-[color:var(--st-text-muted)]">
                Supported formats:{' '}
                {formats.map(f => f.name).join(', ')}
              </p>
            )}
          </div>
        </div>
      ) : (
        /* Split view: list + detail */
        <div className="flex flex-1 overflow-hidden">
          {/* Left: Analysis List */}
          <div className="w-56 shrink-0 min-w-0 border-r border-[color:var(--st-border)] overflow-y-auto">
            {analyses.map(a => {
              const isSelected = selectedId === a.id;
              const v = a.verdict;
              const verdictLabel = v?.verdict || (a.status === 'error' ? 'error' : null);
              const vStyle = verdictLabel && verdictLabel !== 'error'
                ? getVerdictStyle(verdictLabel)
                : null;

              return (
                <div
                  key={a.id}
                  onClick={() => {
                    setSelectedId(a.id);
                    setActiveTab('overview');
                  }}
                  className={`px-3 py-2.5 cursor-pointer border-b border-[color:var(--st-border-subtle)] hover:bg-[color:var(--st-bg-elevated)] transition-colors group ${
                    isSelected ? 'bg-[color:var(--st-bg-elevated)] border-l-2 border-l-blue-500' : ''
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-[color:var(--st-text-primary)] truncate font-medium">
                        {a.fileName}
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        {a.status === 'complete' && (
                          <span className="text-[10px] text-[color:var(--st-text-muted)]">
                            {a.eventCount.toLocaleString()} evt{a.eventCount !== 1 ? 's' : ''}
                          </span>
                        )}
                        {a.status === 'analyzing' && (
                          <span className="text-[10px] text-cyan-400 animate-pulse" aria-live="polite">
                            Analyzing...
                          </span>
                        )}
                        {a.status === 'error' && (
                          <span className="text-[10px] text-red-400">
                            Error
                          </span>
                        )}
                        {verdictLabel && verdictLabel !== 'error' && vStyle && (
                          <Badge
                            variant={verdictLabel === 'clean' ? 'success' : verdictLabel === 'suspicious' ? 'warning' : 'destructive'}
                            size="sm"
                          >
                            {verdictLabel}
                          </Badge>
                        )}
                      </div>
                    </div>
                    {/* Delete button */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDelete(a.id);
                      }}
                      className="opacity-0 group-hover:opacity-100 text-[color:var(--st-text-muted)] hover:text-red-400 transition-all p-0.5"
                      title="Delete analysis"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Detail Pane */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {selected ? (
              <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as SubTab)} className="flex flex-col flex-1 overflow-hidden">
                {/* Sub-tab bar */}
                <TabsList className="px-3 py-1.5 bg-[color:var(--st-bg-panel)] shrink-0">
                  {(
                    [
                      { id: 'overview', label: 'Overview' },
                      { id: 'events', label: 'Events', count: selected.eventCount },
                      { id: 'triage', label: 'Triage' },
                      { id: 'investigation', label: 'Invest.', count: selected.investigation?.chains.length },
                      { id: 'graph', label: 'Graph' },
                      { id: 'verdict', label: 'Verdict' },
                      { id: 'hunting', label: 'Hunting', count: selected.hunting?.length },
                    ] as { id: SubTab; label: string; count?: number }[]
                  ).map(tab => (
                    <TabsTrigger key={tab.id} value={tab.id}>
                      {tab.label}
                      {tab.count !== undefined && tab.count > 0 && (
                        <Badge size="sm" variant="outline" className="ml-1">
                          {tab.count}
                        </Badge>
                      )}
                    </TabsTrigger>
                  ))}
                </TabsList>

                {/* Tab content */}
                <div className="flex-1 overflow-y-auto p-4">
                  {/* Loading / error state */}
                  {selected.status === 'analyzing' && (
                    <div className="flex flex-col items-center justify-center h-full gap-3" aria-live="polite">
                      <div className="animate-spin w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full" />
                      <p className="text-sm text-[color:var(--st-text-muted)]">Analyzing {selected.fileName}...</p>
                    </div>
                  )}

                  {selected.status === 'error' && (
                    <div className="rounded-lg glass-light border border-red-500/30 p-4">
                      <p className="text-sm text-red-400 font-medium mb-1">Analysis Failed</p>
                      <p className="text-xs text-[color:var(--st-text-muted)]">{selected.error || 'Unknown error'}</p>
                    </div>
                  )}

                  {selected.status === 'complete' && (
                    <>
                      {/* OVERVIEW TAB */}
                      {activeTab === 'overview' && (
                        <OverviewTab analysis={selected} />
                      )}

                      {/* EVENTS TAB */}
                      {activeTab === 'events' && (
                        <EventsTab
                          events={pagedEvents}
                          filteredCount={filteredEvents.length}
                          totalCount={selected.eventCount}
                          search={eventSearch}
                          onSearchChange={setEventSearch}
                          severityFilter={eventSeverityFilter}
                          onSeverityFilterChange={setEventSeverityFilter}
                          page={eventPage}
                          totalPages={totalEventPages}
                          onPageChange={setEventPage}
                          expandedIdx={expandedEventIdx}
                          onToggleExpand={setExpandedEventIdx}
                        />
                      )}

                      {/* TRIAGE TAB */}
                      {activeTab === 'triage' && selected.triage && (
                        <TriageTab triage={selected.triage} />
                      )}
                      {activeTab === 'triage' && !selected.triage && (
                        <EmptySection message="No triage data available" />
                      )}

                      {/* INVESTIGATION TAB */}
                      {activeTab === 'investigation' && selected.investigation && (
                        <InvestigationTab
                          investigation={selected.investigation}
                          expandedChains={expandedChains}
                          onToggleChain={(idx) => {
                            setExpandedChains(prev => {
                              const next = new Set(prev);
                              if (next.has(idx)) next.delete(idx);
                              else next.add(idx);
                              return next;
                            });
                          }}
                        />
                      )}
                      {activeTab === 'investigation' && !selected.investigation && (
                        <EmptySection message="No investigation chains found" />
                      )}

                      {/* GRAPH TAB */}
                      {activeTab === 'graph' && selected.graph && (
                        <GraphTab
                          graph={selected.graph}
                          selectedNode={selectedGraphNode}
                          onSelectNode={setSelectedGraphNode}
                          verdict={selected.verdict}
                        />
                      )}
                      {activeTab === 'graph' && !selected.graph && (
                        <EmptySection message="No relationship graph available" />
                      )}

                      {/* VERDICT TAB */}
                      {activeTab === 'verdict' && selected.verdict && (
                        <VerdictTab verdict={selected.verdict} />
                      )}
                      {activeTab === 'verdict' && !selected.verdict && (
                        <EmptySection message="No verdict available" />
                      )}

                      {/* HUNTING TAB */}
                      {activeTab === 'hunting' && selected.hunting && selected.hunting.length > 0 && (
                        <HuntingTab hunting={selected.hunting} />
                      )}
                      {activeTab === 'hunting' && (!selected.hunting || selected.hunting.length === 0) && (
                        <EmptySection message="No hunting query matches — all clear" />
                      )}
                    </>
                  )}
                </div>
              </Tabs>
            ) : (
              <div className="flex items-center justify-center h-full text-[color:var(--st-text-muted)] text-sm">
                Select an analysis to view results
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
