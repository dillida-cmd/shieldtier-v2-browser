/**
 * AnalysisPanel — IOC threat intelligence, content findings, enrichment detail.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import React, { useState, useEffect, useMemo } from 'react';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { ScrollArea } from '../ui/scroll-area';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '../ui/dialog';
import type { InvestigationSession, IOCEntry, IOCType, EnrichmentResult, ContentFinding, ContentFindingSeverity } from '../../types';
import type { IOCGroup, TypeSection } from './panel-types';
import {
  VERDICT_COLORS, PROVIDER_LABELS, SEVERITY_COLORS, CATEGORY_LABELS,
  SEVERITY_ORDER, TYPE_SECTION_LABELS, TYPE_SECTION_ORDER,
  getOverallVerdict, extractHostFromURL,
} from './panel-utils';

// ═══════════════════════════════════════════════════════
// AnalysisPanel
// ═══════════════════════════════════════════════════════

export function AnalysisPanel({ session }: { session: InvestigationSession }) {
  const [iocEntries, setIocEntries] = useState<Map<string, IOCEntry>>(new Map());
  const [selectedIOC, setSelectedIOC] = useState<string | null>(null);
  const [manualInput, setManualInput] = useState('');
  const [querying, setQuerying] = useState(false);
  const [showAPIKeys, setShowAPIKeys] = useState(false);
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());
  const [hideSafe, setHideSafe] = useState(false);
  const [enrichingIOCs, setEnrichingIOCs] = useState<Set<string>>(new Set());
  const [contentFindings, setContentFindings] = useState<ContentFinding[]>([]);
  const [contentFindingsCollapsed, setContentFindingsCollapsed] = useState(true);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  // Listen for live enrichment results
  useEffect(() => {
    const unsub = window.shieldtier.enrichment.onResult((sessionId, entry) => {
      if (sessionId === session.id) {
        setIocEntries(prev => {
          const next = new Map(prev);
          next.set(entry.value.toLowerCase(), entry);
          return next;
        });
        // Clear enriching spinner when done
        if (entry.status === 'done' || entry.status === 'error') {
          setEnrichingIOCs(prev => {
            const next = new Set(prev);
            next.delete(entry.value.toLowerCase());
            return next;
          });
        }
      }
    });
    return () => { unsub(); };
  }, [session.id]);

  // Load existing results when panel mounts
  useEffect(() => {
    (async () => {
      const results = await window.shieldtier.enrichment.getResults(session.id);
      if (results.length > 0) {
        setIocEntries(prev => {
          const next = new Map(prev);
          for (const entry of results) {
            next.set(entry.value.toLowerCase(), entry);
          }
          return next;
        });
      }
    })();
  }, [session.id]);

  // Listen for content analysis findings
  useEffect(() => {
    const unsub = window.shieldtier.contentanalysis.onFinding((sessionId, finding) => {
      if (sessionId === session.id) {
        setContentFindings(prev => [...prev, finding]);
      }
    });
    // Load existing findings
    (async () => {
      const findings = await window.shieldtier.contentanalysis.getFindings(session.id);
      if (findings.length > 0) {
        setContentFindings(findings);
      }
    })();
    return () => { unsub(); };
  }, [session.id]);

  const handleManualQuery = async () => {
    const trimmed = manualInput.trim();
    if (!trimmed || querying) return;
    setQuerying(true);
    try {
      await window.shieldtier.enrichment.query(session.id, trimmed);
      setManualInput('');
    } finally {
      setQuerying(false);
    }
  };

  const handleEnrichIOC = async (iocValue: string) => {
    setEnrichingIOCs(prev => new Set(prev).add(iocValue.toLowerCase()));
    try {
      await window.shieldtier.enrichment.query(session.id, iocValue);
    } catch {
      setEnrichingIOCs(prev => {
        const next = new Set(prev);
        next.delete(iocValue.toLowerCase());
        return next;
      });
    }
  };

  const toggleGroup = (key: string) => {
    setExpandedDomains(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const [collapsedSections, setCollapsedSections] = useState<Set<IOCType>>(new Set(['ip', 'domain', 'url', 'hash'] as IOCType[]));
  const toggleSection = (type: IOCType) => {
    setCollapsedSections(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  // Build type sections with groups inside each
  const typeSections = useMemo((): TypeSection[] => {
    // Bucket entries by IOC type
    const byType = new Map<IOCType, IOCEntry[]>();
    for (const entry of iocEntries.values()) {
      const arr = byType.get(entry.type) || [];
      arr.push(entry);
      byType.set(entry.type, arr);
    }

    const verdictOrder: Record<string, number> = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };

    const sortGroups = (groups: IOCGroup[]) =>
      groups.sort((a, b) => {
        if (a.safe && !b.safe) return 1;
        if (!a.safe && b.safe) return -1;
        const va = verdictOrder[a.overallVerdict] ?? 4;
        const vb = verdictOrder[b.overallVerdict] ?? 4;
        if (va !== vb) return va - vb;
        return b.entries.length - a.entries.length;
      });

    const computeGroupVerdict = (g: IOCGroup) => {
      const verdicts = g.entries.map(e => getOverallVerdict(e));
      if (verdicts.includes('malicious')) g.overallVerdict = 'malicious';
      else if (verdicts.includes('suspicious')) g.overallVerdict = 'suspicious';
      else if (verdicts.some(v => v === 'clean')) g.overallVerdict = 'clean';
      else g.overallVerdict = 'unknown';
      g.safe = g.entries.every(e => e.safe === true);
    };

    const sections: TypeSection[] = [];

    for (const type of TYPE_SECTION_ORDER) {
      const entries = byType.get(type);
      if (!entries || entries.length === 0) continue;

      const groupMap = new Map<string, IOCGroup>();

      if (type === 'domain') {
        // Group domains by parent domain
        for (const entry of entries) {
          const gKey = entry.domain || entry.value.toLowerCase();
          if (!groupMap.has(gKey)) {
            groupMap.set(gKey, { key: `domain:${gKey}`, label: gKey, entries: [], safe: false, overallVerdict: 'unknown' });
          }
          groupMap.get(gKey)!.entries.push(entry);
        }
      } else if (type === 'url') {
        // Group URLs by hostname
        for (const entry of entries) {
          const host = extractHostFromURL(entry.value);
          if (!groupMap.has(host)) {
            groupMap.set(host, { key: `url:${host}`, label: host, entries: [], safe: false, overallVerdict: 'unknown' });
          }
          groupMap.get(host)!.entries.push(entry);
        }
      } else {
        // IPs and hashes — each value is its own group
        for (const entry of entries) {
          const k = entry.value.toLowerCase();
          groupMap.set(k, { key: `${type}:${k}`, label: entry.value, entries: [entry], safe: entry.safe ?? false, overallVerdict: 'unknown' });
        }
      }

      const groups = Array.from(groupMap.values());
      groups.forEach(computeGroupVerdict);
      sortGroups(groups);

      sections.push({
        type,
        label: TYPE_SECTION_LABELS[type],
        groups,
        count: entries.length,
      });
    }

    return sections;
  }, [iocEntries]);

  // Flat list of all groups for summary stat
  const allGroups = typeSections.flatMap(s => s.groups);
  const displaySections = useMemo(() => {
    if (!hideSafe) return typeSections;
    return typeSections
      .map(s => ({ ...s, groups: s.groups.filter(g => !g.safe), count: s.groups.filter(g => !g.safe).reduce((n, g) => n + g.entries.length, 0) }))
      .filter(s => s.groups.length > 0);
  }, [typeSections, hideSafe]);

  const selectedEntry = selectedIOC ? iocEntries.get(selectedIOC.toLowerCase()) : null;

  // Summary counts
  const allEntries = Array.from(iocEntries.values());
  const safeCount = allEntries.filter(e => e.safe).length;
  const nonSafe = allEntries.filter(e => !e.safe);
  const counts = {
    total: allEntries.length,
    malicious: nonSafe.filter(e => getOverallVerdict(e) === 'malicious').length,
    suspicious: nonSafe.filter(e => getOverallVerdict(e) === 'suspicious').length,
    clean: nonSafe.filter(e => getOverallVerdict(e) === 'clean').length,
    pending: nonSafe.filter(e => e.status === 'pending' || e.status === 'enriching').length,
    safe: safeCount,
  };

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <div className="flex-1 flex items-center gap-2">
          <input
            type="text"
            value={manualInput}
            onChange={e => setManualInput(e.target.value)}
            placeholder="Enter IOC (IP, domain, hash, URL)..."
            className="flex-1 max-w-md bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-md px-2.5 py-1 text-[11px] text-[color:var(--st-text-primary)] outline-none focus:border-[color:var(--st-accent)] placeholder-[color:var(--st-text-muted)] font-mono transition-colors"
            onKeyDown={e => { if (e.key === 'Enter') handleManualQuery(); }}
          />
          <button
            type="button"
            onClick={handleManualQuery}
            disabled={!manualInput.trim() || querying}
            className="h-7 px-2.5 rounded-md text-[11px] font-medium bg-[color:var(--st-accent)] text-white hover:brightness-110 disabled:opacity-30 transition-colors cursor-pointer"
          >
            {querying ? 'Querying...' : 'Investigate'}
          </button>
        </div>
        <button
          type="button"
          onClick={() => setShowAPIKeys(true)}
          className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer flex items-center gap-1.5"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 1C3.24 1 1 3.24 1 6s2.24 5 5 5 5-2.24 5-5S8.76 1 6 1zm0 1.5a1.25 1.25 0 110 2.5 1.25 1.25 0 010-2.5zM7.5 9h-3V5.5h3V9z" fill="currentColor"/>
          </svg>
          API Keys
        </button>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-4 px-3 py-1 border-b border-[color:var(--st-border)] text-[10px]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <span className="text-[color:var(--st-text-muted)]">{counts.total} IOCs</span>
        {counts.malicious > 0 && <Badge variant="destructive" size="sm">{counts.malicious} malicious</Badge>}
        {counts.suspicious > 0 && <Badge variant="warning" size="sm">{counts.suspicious} suspicious</Badge>}
        {counts.clean > 0 && <Badge variant="success" size="sm">{counts.clean} clean</Badge>}
        {counts.pending > 0 && <Badge variant="default" size="sm">{counts.pending} pending</Badge>}
        {counts.safe > 0 && <span className="text-[color:var(--st-text-muted)]">{counts.safe} safe/skipped</span>}
        <div className="flex-1" />
        {/* Hide safe toggle */}
        <button
          type="button"
          onClick={() => setHideSafe(!hideSafe)}
          className={cn(
            'h-6 px-2 rounded text-[10px] font-medium flex items-center gap-1 transition-colors cursor-pointer',
            hideSafe ? 'bg-[color:var(--st-purple-dim)] text-[color:var(--st-purple)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
          )}
        >
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
            <path d="M6 1L2 3V5.5C2 8.15 3.71 10.6 6 11.25C8.29 10.6 10 8.15 10 5.5V3L6 1Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
          </svg>
          {hideSafe ? 'Show all' : 'Hide safe'}
          {counts.safe > 0 && <span className="text-[color:var(--st-text-muted)]">({counts.safe})</span>}
        </button>
        <span className="text-[color:var(--st-text-muted)]">{allGroups.length} groups</span>
      </div>

      {/* Main content: type sections + Detail panel */}
      <div className="flex-1 flex overflow-hidden">
        {/* IOC List by type (left) */}
        <div className={cn('flex flex-col overflow-hidden', selectedEntry ? 'w-2/5 border-r border-[color:var(--st-border)]' : 'w-full')}>
          <div className="flex-1 overflow-y-auto">
            {/* Content Findings section */}
            {contentFindings.length > 0 && (
              <ContentFindingsSection
                findings={contentFindings}
                collapsed={contentFindingsCollapsed}
                onToggleCollapse={() => setContentFindingsCollapsed(!contentFindingsCollapsed)}
                expandedFindings={expandedFindings}
                onToggleFinding={(id) => setExpandedFindings(prev => {
                  const next = new Set(prev);
                  if (next.has(id)) next.delete(id); else next.add(id);
                  return next;
                })}
              />
            )}
            {displaySections.length === 0 && contentFindings.length === 0 ? (
              <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
                <div className="text-center">
                  <p className="mb-1">No IOCs detected yet</p>
                  <p className="text-[10px] text-[color:var(--st-text-muted)]">IOCs are auto-extracted from network traffic during capture,<br/>or enter one manually above</p>
                </div>
              </div>
            ) : (
              displaySections.map(section => {
                const isSectionCollapsed = collapsedSections.has(section.type);
                return (
                  <div key={section.type}>
                    {/* Section header */}
                    <button
                      onClick={() => toggleSection(section.type)}
                      className="flex items-center w-full px-3 py-1.5 text-left bg-[color:var(--st-bg-panel)] border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-bg-panel)] transition-colors sticky top-0 z-10"
                    >
                      <svg className={cn('w-3 h-3 text-[color:var(--st-text-muted)] transition-transform shrink-0', !isSectionCollapsed && 'rotate-90')} viewBox="0 0 12 12" fill="none">
                        <path d="M4.5 2.5L8.5 6L4.5 9.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      <span className="ml-2 text-[10px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">{section.label}</span>
                      <span className="ml-2 text-[9px] text-[color:var(--st-text-muted)]">{section.count}</span>
                    </button>

                    {!isSectionCollapsed && section.groups.map(group => {
                      const isExpanded = expandedDomains.has(group.key);
                      const gColors = VERDICT_COLORS[group.overallVerdict] || VERDICT_COLORS.unknown;
                      const allSkipped = group.entries.every(e => e.status === 'skipped');
                      const enrichingGroup = group.entries.some(e => e.status === 'enriching' || enrichingIOCs.has(e.value.toLowerCase()));
                      const isSingleEntry = group.entries.length === 1;
                      const singleEntry = isSingleEntry ? group.entries[0] : null;

                      // For single-entry groups (IPs, hashes), render as a flat row
                      if (isSingleEntry && singleEntry) {
                        const verdict = getOverallVerdict(singleEntry);
                        const colors = VERDICT_COLORS[verdict] || VERDICT_COLORS.unknown;
                        const isSelected = selectedIOC?.toLowerCase() === singleEntry.value.toLowerCase();
                        const isEnriching = singleEntry.status === 'enriching' || enrichingIOCs.has(singleEntry.value.toLowerCase());

                        return (
                          <button
                            key={group.key}
                            onClick={() => setSelectedIOC(isSelected ? null : singleEntry.value)}
                            className={cn(
                              'flex items-center w-full px-3 py-2 text-left hover:bg-[color:var(--st-bg-elevated)] transition-colors border-b border-[color:var(--st-border-subtle)]',
                              isSelected ? 'bg-[color:var(--st-accent-dim)] border-l-2 border-l-[color:var(--st-accent)]' : 'border-l-2 border-l-transparent',
                              group.safe && 'opacity-60'
                            )}
                          >
                            <span className={cn('w-2 h-2 rounded-full shrink-0', colors.dot, isEnriching && 'animate-pulse')} />
                            <div className="ml-2.5 min-w-0 flex-1">
                              <span className={cn('text-xs truncate block font-mono', group.safe ? 'text-[color:var(--st-text-muted)]' : 'text-[color:var(--st-text-primary)]')} title={singleEntry.value}>{singleEntry.value}</span>
                              <div className="flex items-center gap-2 mt-0.5">
                                {singleEntry.status === 'skipped' ? (
                                  <span className="text-[10px] text-[color:var(--st-text-muted)]">skipped</span>
                                ) : (
                                  <Badge size="sm" className={colors.text}>{verdict}</Badge>
                                )}
                                {singleEntry.results.length > 0 && (
                                  <span className="text-[10px] text-[color:var(--st-text-muted)]">{singleEntry.results.length} provider{singleEntry.results.length !== 1 ? 's' : ''}</span>
                                )}
                                {isEnriching && <span className="text-[10px] text-[color:var(--st-accent)]">investigating...</span>}
                              </div>
                            </div>
                            {group.safe && (
                              <svg className="w-3 h-3 text-[color:var(--st-text-muted)] shrink-0 mr-1" viewBox="0 0 12 12" fill="none">
                                <path d="M6 1L2 3V5.5C2 8.15 3.71 10.6 6 11.25C8.29 10.6 10 8.15 10 5.5V3L6 1Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                              </svg>
                            )}
                            {singleEntry.status !== 'enriching' && (
                              <button
                                type="button"
                                className="ml-1 h-5 px-1.5 rounded text-[9px] font-medium text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] hover:brightness-110 border border-[color:var(--st-accent)]/20 transition-colors cursor-pointer"
                                onClick={(e) => { e.stopPropagation(); handleEnrichIOC(singleEntry.value); }}
                              >
                                {singleEntry.status === 'skipped' || singleEntry.status === 'pending' ? 'Investigate' : 'Re-investigate'}
                              </button>
                            )}
                          </button>
                        );
                      }

                      // Multi-entry groups: expandable row
                      return (
                        <div key={group.key}>
                          <button
                            onClick={() => toggleGroup(group.key)}
                            className={cn(
                              'flex items-center w-full px-3 py-2 text-left hover:bg-[color:var(--st-bg-elevated)] transition-colors border-b border-[color:var(--st-border-subtle)]',
                              group.safe && 'opacity-60'
                            )}
                          >
                            <svg className={cn('w-3 h-3 text-[color:var(--st-text-muted)] transition-transform shrink-0', isExpanded && 'rotate-90')} viewBox="0 0 12 12" fill="none">
                              <path d="M4.5 2.5L8.5 6L4.5 9.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                            <span className={cn('ml-2 text-xs truncate font-mono', group.safe ? 'text-[color:var(--st-text-muted)]' : 'text-[color:var(--st-text-primary)]')} title={group.label}>
                              {group.label}
                            </span>
                            {group.safe && (
                              <svg className="ml-1.5 w-3 h-3 text-[color:var(--st-text-muted)] shrink-0" viewBox="0 0 12 12" fill="none">
                                <path d="M6 1L2 3V5.5C2 8.15 3.71 10.6 6 11.25C8.29 10.6 10 8.15 10 5.5V3L6 1Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                              </svg>
                            )}
                            <span className="ml-2 text-[9px] text-[color:var(--st-text-muted)] shrink-0">{group.entries.length}</span>
                            <div className="flex-1" />
                            {enrichingGroup && <span className="text-[10px] text-[color:var(--st-accent)] mr-2 shrink-0">investigating...</span>}
                            {!group.safe && !allSkipped && <span className={cn('w-2 h-2 rounded-full shrink-0', gColors.dot)} />}
                            {allSkipped && <span className="text-[9px] text-[color:var(--st-text-muted)] mr-1 shrink-0">skipped</span>}
                            {!enrichingGroup && (
                              <button
                                type="button"
                                className="ml-2 h-5 px-2 rounded text-[9px] font-medium text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] hover:brightness-110 border border-[color:var(--st-accent)]/20 transition-colors cursor-pointer"
                                onClick={(e) => { e.stopPropagation(); group.entries.forEach(en => handleEnrichIOC(en.value)); }}
                              >
                                {allSkipped ? 'Investigate' : 'Re-investigate'}
                              </button>
                            )}
                          </button>

                          {/* Expanded child entries */}
                          {isExpanded && group.entries.map(entry => {
                            const verdict = getOverallVerdict(entry);
                            const colors = VERDICT_COLORS[verdict] || VERDICT_COLORS.unknown;
                            const isSelected = selectedIOC?.toLowerCase() === entry.value.toLowerCase();
                            const isEnrichingEntry = entry.status === 'enriching' || enrichingIOCs.has(entry.value.toLowerCase());

                            return (
                              <button
                                key={entry.value}
                                onClick={() => setSelectedIOC(isSelected ? null : entry.value)}
                                className={cn(
                                  'flex items-center w-full pl-8 pr-3 py-1.5 text-left hover:bg-[color:var(--st-bg-elevated)] transition-colors',
                                  isSelected ? 'bg-[color:var(--st-accent-dim)] border-l-2 border-l-[color:var(--st-accent)]' : 'border-l-2 border-l-transparent'
                                )}
                              >
                                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', colors.dot, isEnrichingEntry && 'animate-pulse')} />
                                <div className="ml-2 min-w-0 flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className={cn('text-[11px] truncate font-mono', entry.safe ? 'text-[color:var(--st-text-muted)]' : 'text-[color:var(--st-text-primary)]')} title={entry.value}>{entry.value}</span>
                                  </div>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    {entry.status === 'skipped' ? (
                                      <span className="text-[10px] text-[color:var(--st-text-muted)]">skipped</span>
                                    ) : (
                                      <span className={cn('text-[10px]', colors.text)}>{verdict}</span>
                                    )}
                                    {entry.source && (
                                      <span className={cn(
                                        'text-[9px] px-1 py-px rounded font-medium',
                                        entry.source === 'network_traffic' ? 'bg-blue-500/15 text-blue-400' :
                                        entry.source === 'email' ? 'bg-purple-500/15 text-purple-400' :
                                        entry.source === 'pdf_attachment' || entry.source === 'pdf_submitform' ? 'bg-orange-500/15 text-orange-400' :
                                        entry.source === 'pdf_embedded' ? 'bg-orange-500/15 text-orange-400' :
                                        entry.source === 'file_download' ? 'bg-green-500/15 text-green-400' :
                                        entry.source === 'server_address' ? 'bg-cyan-500/15 text-cyan-400' :
                                        entry.source === 'manual' ? 'bg-gray-500/15 text-gray-400' :
                                        entry.source === 'url_chain' ? 'bg-yellow-500/15 text-yellow-400' :
                                        'bg-gray-500/15 text-gray-400'
                                      )}>
                                        {entry.source === 'network_traffic' ? 'BROWSING' :
                                         entry.source === 'email' ? 'EMAIL BODY' :
                                         entry.source === 'pdf_attachment' ? 'PDF /URI' :
                                         entry.source === 'pdf_submitform' ? 'PDF SUBMIT' :
                                         entry.source === 'pdf_embedded' ? 'PDF EMBED' :
                                         entry.source === 'file_download' ? 'DOWNLOAD' :
                                         entry.source === 'server_address' ? 'SERVER IP' :
                                         entry.source === 'manual' ? 'MANUAL' :
                                         entry.source === 'url_chain' ? 'URL CHAIN' :
                                         entry.source.toUpperCase().replace(/_/g, ' ')}
                                      </span>
                                    )}
                                    {entry.results.length > 0 && (
                                      <span className="text-[10px] text-[color:var(--st-text-muted)]">{entry.results.length} provider{entry.results.length !== 1 ? 's' : ''}</span>
                                    )}
                                    {isEnrichingEntry && <span className="text-[10px] text-[color:var(--st-accent)]">investigating...</span>}
                                  </div>
                                </div>
                                {entry.status !== 'enriching' && (
                                  <button
                                    type="button"
                                    className="ml-1 h-5 px-1.5 rounded text-[9px] font-medium text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] hover:brightness-110 border border-[color:var(--st-accent)]/20 transition-colors cursor-pointer"
                                    onClick={(e) => { e.stopPropagation(); handleEnrichIOC(entry.value); }}
                                  >
                                    {entry.status === 'skipped' || entry.status === 'pending' ? 'Investigate' : 'Re-investigate'}
                                  </button>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Detail panel (right) */}
        {selectedEntry && (
          <div className="w-3/5 overflow-y-auto p-4">
            <IOCDetail entry={selectedEntry} onClose={() => setSelectedIOC(null)} session={session} onEnrich={handleEnrichIOC} />
          </div>
        )}
      </div>

      {/* API Keys Modal */}
      {showAPIKeys && <APIKeysModal onClose={() => setShowAPIKeys(false)} />}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// ContentFindingsSection
// ═══════════════════════════════════════════════════════

function ContentFindingsSection({
  findings,
  collapsed,
  onToggleCollapse,
  expandedFindings,
  onToggleFinding,
}: {
  findings: ContentFinding[];
  collapsed: boolean;
  onToggleCollapse: () => void;
  expandedFindings: Set<string>;
  onToggleFinding: (id: string) => void;
}) {
  const [severityFilter, setSeverityFilter] = useState<Set<ContentFindingSeverity>>(new Set(SEVERITY_ORDER));

  const toggleSeverity = (sev: ContentFindingSeverity) => {
    setSeverityFilter(prev => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev); else next.add(sev);
      return next;
    });
  };

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sev of SEVERITY_ORDER) counts[sev] = 0;
    for (const f of findings) counts[f.severity]++;
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() =>
    findings.filter(f => severityFilter.has(f.severity)),
  [findings, severityFilter]);

  return (
    <div>
      <button
        onClick={onToggleCollapse}
        className="flex items-center w-full px-3 py-1.5 text-left bg-[color:var(--st-bg-panel)] border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-bg-panel)] transition-colors sticky top-0 z-10"
      >
        <svg className={cn('w-3 h-3 text-[color:var(--st-text-muted)] transition-transform shrink-0', !collapsed && 'rotate-90')} viewBox="0 0 12 12" fill="none">
          <path d="M4.5 2.5L8.5 6L4.5 9.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="ml-2 text-[10px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">Content Findings</span>
        <span className="ml-2 text-[9px] text-[color:var(--st-text-muted)]">{findings.length}</span>
        <div className="flex-1" />
        <div className="flex gap-2 text-[9px]">
          {severityCounts.critical > 0 && <Badge variant="destructive" size="sm">{severityCounts.critical} critical</Badge>}
          {severityCounts.high > 0 && <Badge variant="warning" size="sm">{severityCounts.high} high</Badge>}
          {severityCounts.medium > 0 && <Badge variant="warning" size="sm" className="bg-yellow-500/15 text-yellow-400">{severityCounts.medium} medium</Badge>}
        </div>
      </button>

      {/* Severity filter bar */}
      {!collapsed && (
        <div className="flex items-center gap-1 px-3 py-1.5 bg-[color:var(--st-bg-base)] border-b border-[color:var(--st-border)]">
          <span className="text-[9px] text-[color:var(--st-text-muted)] mr-1">Filter:</span>
          {SEVERITY_ORDER.map(sev => {
            const count = severityCounts[sev];
            if (count === 0) return null;
            const active = severityFilter.has(sev);
            const sc = SEVERITY_COLORS[sev];
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={cn(
                  'px-1.5 py-0.5 rounded text-[9px] font-medium transition-colors border',
                  active
                    ? `${sc.bg} ${sc.text} border-current/20`
                    : 'bg-transparent text-[color:var(--st-text-muted)] border-[color:var(--st-border)] line-through'
                )}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)} ({count})
              </button>
            );
          })}
          {filteredFindings.length !== findings.length && (
            <span className="text-[9px] text-[color:var(--st-text-muted)] ml-auto">
              Showing {filteredFindings.length}/{findings.length}
            </span>
          )}
        </div>
      )}

      {!collapsed && filteredFindings.map(finding => {
        const sColors = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info;
        const isExpanded = expandedFindings.has(finding.id);
        let hostname = '';
        try { hostname = new URL(finding.url).hostname; } catch {}

        return (
          <div key={finding.id} className="border-b border-[color:var(--st-border-subtle)]">
            <button
              onClick={() => onToggleFinding(finding.id)}
              className="flex items-center w-full px-3 py-1.5 text-left hover:bg-[color:var(--st-bg-panel)] transition-colors gap-2"
            >
              <Badge size="sm" className={cn(sColors.bg, sColors.text)}>
                {finding.severity.toUpperCase()}
              </Badge>
              <span className="text-[10px] text-[color:var(--st-text-muted)] shrink-0">{CATEGORY_LABELS[finding.category] || finding.category}</span>
              <span className="text-[10px] text-[color:var(--st-text-muted)] truncate flex-1">{finding.description}</span>
              {hostname && <span className="text-[9px] text-[color:var(--st-text-muted)] shrink-0 max-w-[120px] truncate font-mono">{hostname}</span>}
              <svg className={cn('w-2.5 h-2.5 text-[color:var(--st-text-muted)] transition-transform shrink-0', isExpanded && 'rotate-180')} viewBox="0 0 12 12" fill="none">
                <path d="M3 5L6 8L9 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            {isExpanded && (
              <div className="px-3 pb-2 ml-6">
                <div className="bg-[color:var(--st-bg-base)] rounded px-2 py-1.5 border border-[color:var(--st-border-subtle)]">
                  <p className="text-[10px] text-[color:var(--st-text-muted)] mb-1">Evidence:</p>
                  <pre className="text-[10px] text-[color:var(--st-text-muted)] whitespace-pre-wrap break-all font-mono leading-relaxed">{finding.evidence}</pre>
                  <div className="mt-1.5 flex gap-3 text-[9px] text-[color:var(--st-text-muted)]">
                    <span>URL: <span className="font-mono">{finding.url.slice(0, 80)}{finding.url.length > 80 ? '...' : ''}</span></span>
                    <span>MIME: {finding.mimeType}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// DetailValue
// ═══════════════════════════════════════════════════════

function DetailValue({ label, value }: { label: string; value: any }) {
  const [expanded, setExpanded] = useState(false);

  // String / number / boolean — render as-is (with truncation for long strings)
  if (typeof value !== 'object') {
    const str = String(value);
    if (str.length > 200 && !expanded) {
      return (
        <div className="flex items-start gap-2">
          <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
          <div className="flex-1 min-w-0">
            <span className="text-[color:var(--st-text-muted)] break-all font-mono">{str.slice(0, 200)}...</span>
            <button type="button" className="ml-1 text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer" onClick={() => setExpanded(true)}>Show more</button>
          </div>
        </div>
      );
    }
    return (
      <div className="flex items-start gap-2">
        <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
        <span className="text-[color:var(--st-text-muted)] break-all font-mono">{str}</span>
        {expanded && <button type="button" className="ml-1 text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer shrink-0" onClick={() => setExpanded(false)}>Less</button>}
      </div>
    );
  }

  // Array of strings — render as pill badges
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

  // Array of objects — render as mini cards
  if (Array.isArray(value) && value.length > 0) {
    const displayItems = expanded ? value : value.slice(0, 5);
    return (
      <div>
        <span className="text-[color:var(--st-text-muted)] text-[10px]">{label} ({value.length})</span>
        <div className="mt-1 space-y-1">
          {displayItems.map((item, i) => {
            const name = item.name || item.title || item.id || `#${i + 1}`;
            const tags = item.tags || item.labels;
            const created = item.created || item.created_at || item.date;
            return (
              <div key={i} className="bg-[color:var(--st-bg-panel)] rounded px-2 py-1.5 border border-[color:var(--st-border)]">
                <div className="text-[color:var(--st-text-secondary)] text-[11px] font-medium truncate">{name}</div>
                <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-0.5">
                  {created && <span className="text-[9px] text-[color:var(--st-text-muted)] font-mono">Created: {String(created).slice(0, 10)}</span>}
                  {Array.isArray(tags) && tags.length > 0 && (
                    <div className="flex gap-0.5 flex-wrap">
                      {tags.map((t: string, j: number) => (
                        <Badge key={j} variant="outline" size="sm">{t}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
        {value.length > 5 && (
          <button type="button" className="mt-1 text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer" onClick={() => setExpanded(!expanded)}>
            {expanded ? 'Show less' : `Show all ${value.length}`}
          </button>
        )}
      </div>
    );
  }

  // Empty array
  if (Array.isArray(value) && value.length === 0) {
    return (
      <div className="flex items-start gap-2">
        <span className="text-[color:var(--st-text-muted)] w-20 shrink-0">{label}</span>
        <span className="text-[color:var(--st-text-muted)] italic">None</span>
      </div>
    );
  }

  // Nested object — render as indented key-value rows
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
              <span className="text-[color:var(--st-text-muted)] text-[10px] break-all font-mono">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return null;
}

// ═══════════════════════════════════════════════════════
// IOCDetail
// ═══════════════════════════════════════════════════════

function IOCDetail({ entry, onClose, session, onEnrich }: { entry: IOCEntry; onClose: () => void; session?: InvestigationSession; onEnrich?: (ioc: string) => void }) {
  const verdict = getOverallVerdict(entry);
  const colors = VERDICT_COLORS[verdict] || VERDICT_COLORS.unknown;
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set());

  // Close detail panel on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const toggleExpand = (provider: string) => {
    setExpandedProviders(prev => {
      const next = new Set(prev);
      if (next.has(provider)) next.delete(provider);
      else next.add(provider);
      return next;
    });
  };

  return (
    <div className="text-xs">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={cn('w-2.5 h-2.5 rounded-full', colors.dot)} />
            <span className="text-sm text-[color:var(--st-text-primary)] font-medium break-all font-mono">{entry.value}</span>
            {entry.safe && (
              <Badge variant="outline" size="sm">safe</Badge>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-[color:var(--st-text-muted)] ml-4">
            <span className="uppercase">{entry.type}</span>
            <span>Source: {entry.source}</span>
            <span className="font-mono">First seen: {new Date(entry.firstSeen).toLocaleTimeString()}</span>
          </div>
        </div>
        <button type="button" onClick={onClose} className="h-6 w-6 rounded flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer">
          <svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 3L9 9M9 3L3 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
        </button>
      </div>

      {/* Manual enrich banner */}
      {entry.status !== 'enriching' && onEnrich && (
        <div className="flex items-center gap-3 rounded-lg px-3 py-2 mb-4 bg-[color:var(--st-accent-dim)] border border-[color:var(--st-accent)]/20">
          <span className="text-[11px] text-[color:var(--st-text-muted)] flex-1">
            {entry.status === 'skipped'
              ? 'Investigation skipped (safe/infrastructure domain). Investigate manually to check threat intel.'
              : entry.status === 'done' || entry.status === 'error'
              ? 'Re-investigate this IOC to refresh threat intel data.'
              : 'Investigate this IOC to query threat intel providers.'}
          </span>
          <button
            type="button"
            className="h-6 px-2 rounded text-[10px] font-medium text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] hover:brightness-110 border border-[color:var(--st-accent)]/30 transition-colors cursor-pointer"
            onClick={() => onEnrich(entry.value)}
          >
            {entry.status === 'done' || entry.status === 'error' ? 'Re-investigate' : 'Investigate now'}
          </button>
        </div>
      )}

      {/* Overall verdict */}
      <div className={cn('rounded-lg px-3 py-2 mb-4', colors.bg)}>
        <span className={cn('text-xs font-medium capitalize', colors.text)}>
          Overall: {entry.status === 'skipped' ? 'skipped' : verdict}
        </span>
        {entry.status === 'enriching' && (
          <span className="ml-2 text-[10px] text-[color:var(--st-accent)]">Enriching...</span>
        )}
      </div>

      {/* Provider results */}
      <div className="space-y-2">
        {entry.results.length === 0 && entry.status !== 'enriching' && entry.status !== 'skipped' && (
          <p className="text-[color:var(--st-text-muted)] text-center py-4">No investigation results yet</p>
        )}
        {entry.results.length === 0 && entry.status === 'skipped' && (
          <p className="text-[color:var(--st-text-muted)] text-center py-4">No investigation data — click "Investigate now" to query threat intel providers</p>
        )}
        {entry.results.map((result, i) => {
          const rColors = VERDICT_COLORS[result.verdict] || VERDICT_COLORS.unknown;
          const isExpanded = expandedProviders.has(result.provider);

          return (
            <div key={`${result.provider}-${i}`} className="bg-[color:var(--st-bg-base)] rounded-lg border border-[color:var(--st-border)]">
              <button
                onClick={() => toggleExpand(result.provider)}
                className="flex items-center w-full px-3 py-2 text-left hover:bg-[color:var(--st-bg-panel)] rounded-lg transition-colors"
              >
                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', rColors.dot)} />
                <span className="ml-2 text-[color:var(--st-text-secondary)] font-medium shrink-0">{PROVIDER_LABELS[result.provider] || result.provider}</span>
                <span className="flex-1 ml-3 text-[color:var(--st-text-muted)] truncate">{result.summary}</span>
                <Badge size="sm" className={cn(rColors.text, 'capitalize')}>{result.verdict}</Badge>
                <svg className={cn('ml-2 w-3 h-3 text-[color:var(--st-text-muted)] transition-transform', isExpanded && 'rotate-180')} viewBox="0 0 12 12" fill="none">
                  <path d="M3 5L6 8L9 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
              {isExpanded && (
                <div className="px-3 pb-2 pt-0">
                  <div className="border-t border-[color:var(--st-border)] pt-2 space-y-1">
                    {result.confidence > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-[color:var(--st-text-muted)] w-20">Confidence</span>
                        <div className="flex-1 h-1.5 bg-[color:var(--st-bg-panel)] rounded-full overflow-hidden">
                          <div className={cn('h-full rounded-full', rColors.dot)} style={{ width: `${result.confidence}%` }} />
                        </div>
                        <span className="text-[color:var(--st-text-muted)] w-8 text-right font-mono">{result.confidence}%</span>
                      </div>
                    )}
                    {Object.entries(result.details).map(([key, value]) => {
                      if (value === null || value === undefined || key === 'body') return null;
                      return <DetailValue key={key} label={key} value={value} />;
                    })}
                    {result.error && (
                      <div className="flex items-start gap-2">
                        <span className="text-[color:var(--st-danger)] w-20 shrink-0">Error</span>
                        <span className="text-[color:var(--st-danger)]">{result.error}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// APIKeysModal
// ═══════════════════════════════════════════════════════

function APIKeysModal({ onClose }: { onClose: () => void }) {
  const [keys, setKeys] = useState<Record<string, string>>({
    virustotal: '',
    abuseipdb: '',
    otx: '',
    urlhaus: '',
    misp_url: '',
    misp: '',
  });
  const [maskedKeys, setMaskedKeys] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    (async () => {
      const masked = await window.shieldtier.enrichment.getAPIKeys();
      setMaskedKeys(masked);
    })();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    // Only send keys that were actually changed (non-empty)
    const toSave: Record<string, string> = {};
    for (const [k, v] of Object.entries(keys)) {
      if (v.trim()) toSave[k] = v.trim();
    }
    await window.shieldtier.enrichment.setAPIKeys(toSave);
    setSaving(false);
    setSaved(true);
    const masked = await window.shieldtier.enrichment.getAPIKeys();
    setMaskedKeys(masked);
    setTimeout(() => setSaved(false), 2000);
  };

  const providers = [
    { key: 'virustotal', label: 'VirusTotal', hint: 'Free tier: 4 req/min' },
    { key: 'abuseipdb', label: 'AbuseIPDB', hint: 'Free tier: 1000 req/day' },
    { key: 'otx', label: 'AlienVault OTX', hint: 'Optional — higher rate limits with key' },
    { key: 'urlhaus', label: 'URLhaus', hint: 'No key required — optional auth token' },
    { key: 'misp_url', label: 'MISP Instance URL', hint: 'e.g. https://misp.yourorg.com', secret: false },
    { key: 'misp', label: 'MISP API Key', hint: 'Auth key from your MISP instance', secret: true },
  ];

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="w-[500px] max-w-[90vw]">
        <DialogHeader>
          <DialogTitle>API Key Configuration</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          {providers.map(p => (
            <div key={p.key}>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs text-[color:var(--st-text-secondary)]">{p.label}</label>
                {maskedKeys[p.key] && (
                  <Badge variant="success" size="sm">configured ({maskedKeys[p.key]})</Badge>
                )}
              </div>
              <input
                type={p.secret === false ? 'text' : 'password'}
                value={keys[p.key] || ''}
                onChange={e => setKeys(prev => ({ ...prev, [p.key]: e.target.value }))}
                placeholder={maskedKeys[p.key] ? `Current: ${maskedKeys[p.key]}` : p.secret === false ? 'Enter URL...' : 'Enter API key...'}
                className="w-full bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-md px-2.5 py-1.5 text-[12px] text-[color:var(--st-text-primary)] outline-none focus:border-[color:var(--st-accent)] placeholder-[color:var(--st-text-muted)] font-mono transition-colors"
              />
              <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">{p.hint}</p>
            </div>
          ))}
          <p className="text-[10px] text-[color:var(--st-text-muted)]">WHOIS lookups use a free API and require no key.</p>
        </div>
        <DialogFooter>
          {saved && <Badge variant="success" size="sm" className="mr-2">Saved!</Badge>}
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Keys'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
