/**
 * NetworkPanel — Live HAR table with domain grouping, whitelist, and detail view.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/tabs';
import { ScrollArea } from '../ui/scroll-area';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '../ui/dialog';
import type { HAREntry, DomainWhitelist } from '../../types';
import type { DomainGroup, NetworkViewMode } from './panel-types';
import {
  extractPath, extractHost, formatNetSize, formatNetTime,
  getStatusColor, getMethodColor, categorizeDomain,
  matchWildcardClient, BUILT_IN_PATTERNS, CATEGORY_CONFIG,
} from './panel-utils';

// ═══════════════════════════════════════════════════════
// NetworkPanel
// ═══════════════════════════════════════════════════════

export function NetworkPanel({ entries, captureEnabled, onToggleCapture, onExportHAR }: {
  entries: HAREntry[];
  captureEnabled: boolean;
  onToggleCapture: () => void;
  onExportHAR: () => void;
}) {
  const tableRef = useRef<HTMLDivElement>(null);
  const [selectedEntry, setSelectedEntry] = useState<HAREntry | null>(null);
  const [viewMode, setViewMode] = useState<NetworkViewMode>('grouped');
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());
  const [hideWhitelisted, setHideWhitelisted] = useState(false);
  const [whitelist, setWhitelist] = useState<DomainWhitelist>({ domains: [], patterns: [], useBuiltIn: true });
  const [showWhitelistEditor, setShowWhitelistEditor] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; domain: string } | null>(null);

  // Load whitelist from config
  useEffect(() => {
    (async () => {
      try {
        const wl = await window.shieldtier.config.getWhitelist();
        setWhitelist(wl);
      } catch {}
    })();
  }, []);

  // Close context menu on click elsewhere or Escape
  useEffect(() => {
    if (!contextMenu) return;
    const handleClick = () => setContextMenu(null);
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setContextMenu(null);
    };
    document.addEventListener('click', handleClick);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('click', handleClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [contextMenu]);

  // Check if domain matches whitelist (client-side quick check)
  const isDomainWhitelisted = useCallback((domain: string): boolean => {
    const ld = domain.toLowerCase();
    if (whitelist.domains.some(d => d.toLowerCase() === ld)) return true;
    if (whitelist.patterns.some(p => matchWildcardClient(p, ld))) return true;
    if (whitelist.useBuiltIn && BUILT_IN_PATTERNS.some(p => matchWildcardClient(p, ld))) return true;
    return false;
  }, [whitelist]);

  // Auto-scroll to bottom when new entries arrive (flat view only)
  useEffect(() => {
    if (viewMode === 'flat' && tableRef.current) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight;
    }
  }, [entries.length, viewMode]);

  // Build domain groups
  const domainGroups = useMemo(() => {
    const groups = new Map<string, DomainGroup>();
    for (const entry of entries) {
      const domain = extractHost(entry.request.url) || 'unknown';
      if (!groups.has(domain)) {
        groups.set(domain, { domain, entries: [], totalSize: 0, errorCount: 0, isWhitelisted: isDomainWhitelisted(domain), category: 'other' });
      }
      const g = groups.get(domain)!;
      g.entries.push(entry);
      g.totalSize += entry.response.bodySize > 0 ? entry.response.bodySize : 0;
      if (entry.response.status >= 400) g.errorCount++;
    }
    // Compute category for each group
    for (const g of groups.values()) {
      g.category = categorizeDomain(g.domain, g.entries);
    }
    // Sort by request count (most active first)
    return Array.from(groups.values()).sort((a, b) => b.entries.length - a.entries.length);
  }, [entries, isDomainWhitelisted]);

  const toggleDomain = (domain: string) => {
    setExpandedDomains(prev => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  };

  const handleAddToWhitelist = async (domain: string) => {
    const updated = { ...whitelist, domains: [...whitelist.domains, domain] };
    setWhitelist(updated);
    await window.shieldtier.config.setWhitelist(updated);
    setContextMenu(null);
  };

  const handleRemoveFromWhitelist = async (domain: string) => {
    const updated = {
      ...whitelist,
      domains: whitelist.domains.filter(d => d.toLowerCase() !== domain.toLowerCase()),
      patterns: whitelist.patterns.filter(p => !matchWildcardClient(p, domain.toLowerCase())),
    };
    setWhitelist(updated);
    await window.shieldtier.config.setWhitelist(updated);
    setContextMenu(null);
  };

  // Filter groups for display
  const displayGroups = hideWhitelisted
    ? domainGroups.filter(g => !g.isWhitelisted)
    : domainGroups;

  // Unique domain count for toolbar
  const domainCount = domainGroups.length;
  const whitelistedCount = domainGroups.filter(g => g.isWhitelisted).length;

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar — macOS toolbar style */}
      <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <button
          type="button"
          onClick={onToggleCapture}
          className={cn(
            'h-7 px-2.5 rounded-md text-[11px] font-medium flex items-center gap-1.5 border transition-colors cursor-pointer',
            captureEnabled
              ? 'bg-[color:var(--st-danger-dim)] text-[color:var(--st-danger)] border-[color:var(--st-danger)]/20'
              : 'bg-transparent text-[color:var(--st-text-muted)] border-[color:var(--st-border)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]'
          )}
        >
          <span className={cn('w-1.5 h-1.5 rounded-full', captureEnabled ? 'bg-[color:var(--st-danger)] animate-pulse' : 'bg-[color:var(--st-text-muted)]')} />
          {captureEnabled ? 'Stop' : 'Record'}
        </button>
        <button
          type="button"
          onClick={onExportHAR}
          disabled={entries.length === 0}
          className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer"
        >
          Export HAR
        </button>
        <span className="w-px h-4 bg-[color:var(--st-border)] mx-0.5" />
        {/* View mode toggle — segmented control */}
        <div className="flex items-center bg-[color:var(--st-bg-base)] rounded-md border border-[color:var(--st-border)] p-px">
          <button
            type="button"
            onClick={() => setViewMode('grouped')}
            className={cn(
              'h-[22px] px-2 rounded text-[10px] font-medium transition-colors cursor-pointer',
              viewMode === 'grouped' ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
            )}
          >
            By Domain
          </button>
          <button
            type="button"
            onClick={() => setViewMode('flat')}
            className={cn(
              'h-[22px] px-2 rounded text-[10px] font-medium transition-colors cursor-pointer',
              viewMode === 'flat' ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
            )}
          >
            Flat
          </button>
        </div>
        <span className="w-px h-4 bg-[color:var(--st-border)] mx-0.5" />
        {/* Whitelist controls */}
        <button
          type="button"
          onClick={() => setHideWhitelisted(!hideWhitelisted)}
          title="Hide whitelisted domains"
          className={cn(
            'h-7 px-2 rounded-md text-[10px] font-medium flex items-center gap-1 transition-colors cursor-pointer',
            hideWhitelisted ? 'bg-[color:var(--st-purple-dim)] text-[color:var(--st-purple)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]'
          )}
        >
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
            <path d="M6 1L2 3V5.5C2 8.15 3.71 10.6 6 11.25C8.29 10.6 10 8.15 10 5.5V3L6 1Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
          </svg>
          {hideWhitelisted ? 'Show all' : 'Hide safe'}
          {whitelistedCount > 0 && <span className="text-[color:var(--st-text-muted)]">({whitelistedCount})</span>}
        </button>
        <button
          type="button"
          onClick={() => setShowWhitelistEditor(true)}
          title="Edit whitelist"
          className="h-7 px-2 rounded-md text-[10px] font-medium text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer"
        >
          Whitelist
        </button>
        <div className="flex-1" />
        <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono">{entries.length} requests</span>
        {viewMode === 'grouped' && <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono ml-2">{domainCount} domains</span>}
      </div>

      {/* Table + Detail split */}
      <div className="flex-1 flex overflow-hidden">
        {/* Request list */}
        <div className={cn('flex flex-col', selectedEntry ? 'w-1/2 border-r border-[color:var(--st-border)]' : 'w-full')}>

          {viewMode === 'flat' && (
            <>
              {/* Table header */}
              <Table className="text-[10px]">
                <TableHeader>
                  <TableRow className="bg-[color:var(--st-bg-panel)] border-b border-[color:var(--st-border)]">
                    <TableHead className="w-14 h-7 py-1 px-3">Method</TableHead>
                    <TableHead className="w-14 h-7 py-1 px-3 text-right">Status</TableHead>
                    <TableHead className="h-7 py-1 px-2">URL</TableHead>
                    <TableHead className="w-16 h-7 py-1 px-3 text-right">Size</TableHead>
                    <TableHead className="w-16 h-7 py-1 px-3 text-right">Time</TableHead>
                  </TableRow>
                </TableHeader>
              </Table>
              <div ref={tableRef} className="flex-1 overflow-y-auto">
                {entries.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
                    {captureEnabled ? 'Waiting for network requests...' : 'Click Record to start capturing network traffic'}
                  </div>
                ) : (
                  entries.map((entry, i) => (
                    <NetworkRow key={`${entry.requestId}-${i}`} entry={entry} selected={selectedEntry?.requestId === entry.requestId} onSelect={setSelectedEntry} showHost even={i % 2 === 0} />
                  ))
                )}
              </div>
            </>
          )}

          {viewMode === 'grouped' && (
            <div ref={tableRef} className="flex-1 overflow-y-auto">
              {entries.length === 0 ? (
                <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
                  {captureEnabled ? 'Waiting for network requests...' : 'Click Record to start capturing network traffic'}
                </div>
              ) : (
                displayGroups.map(group => {
                  const isExpanded = expandedDomains.has(group.domain);
                  return (
                    <div key={group.domain}>
                      {/* Domain header */}
                      <button
                        onClick={() => toggleDomain(group.domain)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setContextMenu({ x: e.clientX, y: e.clientY, domain: group.domain });
                        }}
                        className={cn(
                          'flex items-center w-full px-3 py-1.5 border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-border-subtle)] transition-colors text-left cursor-pointer',
                          group.isWhitelisted && 'opacity-50'
                        )}
                      >
                        <svg className={cn('w-3 h-3 text-[color:var(--st-text-muted)] mr-2 transition-transform shrink-0', isExpanded && 'rotate-90')} viewBox="0 0 12 12" fill="none">
                          <path d="M4 2L8 6L4 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                        {group.isWhitelisted && (
                          <svg className="w-3 h-3 text-purple-500/60 mr-1.5 shrink-0" viewBox="0 0 12 12" fill="none">
                            <path d="M6 1L2 3V5.5C2 8.15 3.71 10.6 6 11.25C8.29 10.6 10 8.15 10 5.5V3L6 1Z" stroke="currentColor" strokeWidth="1" fill="currentColor" fillOpacity="0.15" />
                          </svg>
                        )}
                        <span className={cn('text-xs font-medium truncate font-mono', group.isWhitelisted ? 'text-[color:var(--st-text-muted)]' : 'text-[color:var(--st-text-secondary)]')}>{group.domain}</span>
                        <Badge size="sm" className={cn('ml-1.5 shrink-0', CATEGORY_CONFIG[group.category].color)}>
                          {CATEGORY_CONFIG[group.category].label}
                        </Badge>
                        <span className="ml-2 text-[10px] text-[color:var(--st-text-muted)] shrink-0 font-mono">{group.entries.length} req{group.entries.length !== 1 ? 's' : ''}</span>
                        <span className="ml-2 text-[10px] text-[color:var(--st-text-muted)] shrink-0 font-mono">{formatNetSize(group.totalSize)}</span>
                        {group.errorCount > 0 && (
                          <Badge variant="destructive" size="sm" className="ml-2 shrink-0">
                            {group.errorCount} error{group.errorCount !== 1 ? 's' : ''}
                          </Badge>
                        )}
                      </button>
                      {/* Expanded entries */}
                      {isExpanded && group.entries.map((entry, i) => (
                        <NetworkRow key={`${entry.requestId}-${i}`} entry={entry} selected={selectedEntry?.requestId === entry.requestId} onSelect={setSelectedEntry} showHost={false} indent />
                      ))}
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selectedEntry && (
          <div className="w-1/2 overflow-y-auto p-3">
            <RequestDetail entry={selectedEntry} onClose={() => setSelectedEntry(null)} />
          </div>
        )}
      </div>

      {/* Right-click context menu */}
      {contextMenu && (
        <div
          className="fixed z-50 bg-[color:var(--st-bg-elevated)] border border-[color:var(--st-border)] rounded-lg shadow-xl py-1 min-w-[180px]"
          style={{
            left: Math.min(contextMenu.x, window.innerWidth - 200),
            top: Math.min(contextMenu.y, window.innerHeight - 60),
          }}
          onClick={e => e.stopPropagation()}
        >
          {isDomainWhitelisted(contextMenu.domain) ? (
            <button
              onClick={() => handleRemoveFromWhitelist(contextMenu.domain)}
              className="w-full px-3 py-1.5 text-xs text-left text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-accent-dim)] transition-colors"
            >
              Remove from whitelist
            </button>
          ) : (
            <button
              onClick={() => handleAddToWhitelist(contextMenu.domain)}
              className="w-full px-3 py-1.5 text-xs text-left text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-accent-dim)] transition-colors"
            >
              Add to whitelist
            </button>
          )}
        </div>
      )}

      {/* Whitelist Editor Modal */}
      {showWhitelistEditor && (
        <WhitelistEditor
          whitelist={whitelist}
          onSave={(wl) => { setWhitelist(wl); setShowWhitelistEditor(false); }}
          onClose={() => setShowWhitelistEditor(false)}
        />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// NetworkRow
// ═══════════════════════════════════════════════════════

function NetworkRow({ entry, selected, onSelect, showHost, indent, even }: {
  entry: HAREntry;
  selected: boolean;
  onSelect: (entry: HAREntry | null) => void;
  showHost: boolean;
  indent?: boolean;
  even?: boolean;
}) {
  return (
    <button
      onClick={() => onSelect(selected ? null : entry)}
      className={cn(
        'flex items-center w-full text-[11px] px-3 py-1 hover:bg-[color:var(--st-border-subtle)] transition-colors text-left cursor-pointer',
        selected ? 'bg-[color:var(--st-accent-dim)] border-l-2 border-l-[color:var(--st-accent)]' : 'border-l-2 border-l-transparent',
        indent && 'pl-7',
        even && !selected && 'bg-[color:var(--st-bg-elevated)]/30',
      )}
    >
      <Badge
        size="sm"
        className={cn('w-14 shrink-0 justify-center font-mono', getMethodColor(entry.request.method))}
      >
        {entry.request.method}
      </Badge>
      <span className={cn('w-14 shrink-0 text-right font-mono', getStatusColor(entry.response.status))}>
        {entry.response.status || '-'}
      </span>
      <span className="flex-1 px-2 truncate text-[color:var(--st-text-secondary)] font-mono" title={entry.request.url}>
        {showHost && <span className="text-[color:var(--st-text-muted)]">{extractHost(entry.request.url)}</span>}
        {extractPath(entry.request.url)}
      </span>
      <span className="w-16 text-right shrink-0 text-[color:var(--st-text-muted)] font-mono">
        {formatNetSize(entry.response.bodySize)}
      </span>
      <span className="w-16 text-right shrink-0 text-[color:var(--st-text-muted)] font-mono">
        {formatNetTime(entry.time)}
      </span>
    </button>
  );
}

// ═══════════════════════════════════════════════════════
// RequestDetail
// ═══════════════════════════════════════════════════════

function RequestDetail({ entry, onClose }: { entry: HAREntry; onClose: () => void }) {
  const hasRequestBody = !!entry.request.postData?.text;
  const hasResponseBody = !!entry.response.content?.text;
  const responseMime = entry.response.content?.mimeType || '';

  // Default tab: show Response for GET (no request body), Headers otherwise
  const [tab, setTab] = useState<string>('headers');

  // Smart JSON formatter — keeps flat arrays compact, expands nested structures
  const formatBody = (text: string, mime: string): { formatted: string; isJson: boolean } => {
    if (mime.includes('json') || mime.includes('protobuf') || text.trimStart().startsWith('{') || text.trimStart().startsWith('[')) {
      try {
        const parsed = JSON.parse(text);
        return { formatted: smartStringify(parsed, 0), isJson: true };
      } catch { /* not valid JSON */ }
    }
    // Try to parse form-urlencoded
    if (mime.includes('form-urlencoded')) {
      try {
        const params = new URLSearchParams(text);
        const lines: string[] = [];
        params.forEach((v, k) => lines.push(`${k} = ${v}`));
        return { formatted: lines.join('\n'), isJson: false };
      } catch { /* keep raw */ }
    }
    return { formatted: text, isJson: false };
  };

  function smartStringify(val: any, depth: number): string {
    const indent = '  '.repeat(depth);
    const childIndent = '  '.repeat(depth + 1);

    if (val === null) return 'null';
    if (typeof val === 'string') return JSON.stringify(val);
    if (typeof val !== 'object') return String(val);

    if (Array.isArray(val)) {
      if (val.length === 0) return '[]';
      // Flat array (all primitives) — try compact single line
      const allPrimitive = val.every(v => v === null || typeof v !== 'object');
      if (allPrimitive) {
        const compact = '[' + val.map(v => v === null ? 'null' : JSON.stringify(v)).join(', ') + ']';
        if (compact.length < 80) return compact;
        // Multi-line but grouped (up to ~80 chars per line)
        const items = val.map(v => v === null ? 'null' : JSON.stringify(v));
        const lines: string[] = [];
        let line = '';
        for (const item of items) {
          if (line && (line + ', ' + item).length > 76) {
            lines.push(childIndent + line + ',');
            line = item;
          } else {
            line = line ? line + ', ' + item : item;
          }
        }
        if (line) lines.push(childIndent + line);
        return '[\n' + lines.join('\n') + '\n' + indent + ']';
      }
      // Mixed array — expand each item
      const items = val.map(v => childIndent + smartStringify(v, depth + 1));
      return '[\n' + items.join(',\n') + '\n' + indent + ']';
    }

    // Object
    const keys = Object.keys(val);
    if (keys.length === 0) return '{}';
    const entries = keys.map(k => {
      const v = smartStringify(val[k], depth + 1);
      return childIndent + JSON.stringify(k) + ': ' + v;
    });
    return '{\n' + entries.join(',\n') + '\n' + indent + '}';
  }

  // Parse URL parts
  const urlParts = useMemo(() => {
    try {
      const u = new URL(entry.request.url);
      const queryParams: { name: string; value: string }[] = [];
      u.searchParams.forEach((v, k) => queryParams.push({ name: k, value: v }));
      return { scheme: u.protocol.replace(':', ''), host: u.hostname, port: u.port, path: u.pathname, query: u.search, queryParams, fragment: u.hash };
    } catch {
      return null;
    }
  }, [entry.request.url]);

  // Extract cookies from request headers
  const cookies = useMemo(() => {
    const cookieHeader = entry.request.headers.find(h => h.name.toLowerCase() === 'cookie');
    if (!cookieHeader) return [];
    return cookieHeader.value.split(';').map(c => {
      const [name, ...rest] = c.trim().split('=');
      return { name: name.trim(), value: rest.join('=').trim() };
    }).filter(c => c.name);
  }, [entry.request.headers]);

  // Use queryString from HAR or parsed from URL
  const queryParams = entry.request.queryString.length > 0
    ? entry.request.queryString
    : (urlParts?.queryParams || []);

  // Close detail panel on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="text-xs">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-0.5">
          {(['headers', 'payload', 'response', 'timing'] as const).map(t => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={cn(
                'px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer capitalize',
                tab === t
                  ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]'
                  : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]'
              )}
            >
              {t}
              {t === 'payload' && (hasRequestBody || queryParams.length > 0) && <span className="ml-1 w-1 h-1 rounded-full bg-[color:var(--st-accent)] inline-block" />}
              {t === 'response' && hasResponseBody && <span className="ml-1 w-1 h-1 rounded-full bg-[color:var(--st-success)] inline-block" />}
            </button>
          ))}
        </div>
        <button type="button" onClick={onClose} className="w-6 h-6 rounded flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] cursor-pointer">
          <svg width="10" height="10" viewBox="0 0 12 12"><path d="M3 3L9 9M9 3L3 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
        </button>
      </div>

      {tab === 'headers' && (
        <div className="space-y-3">
          <div>
            <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">General</p>
            <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1">
              <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">URL: </span><span className="font-mono break-all">{entry.request.url}</span></p>
              <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Method: </span><span className="font-mono">{entry.request.method}</span></p>
              <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Status: </span><span className="font-mono">{entry.response.status} {entry.response.statusText}</span></p>
              {entry.serverIPAddress && (
                <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Remote: </span><span className="font-mono">{entry.serverIPAddress}</span></p>
              )}
              {entry.resourceType && (
                <p className="text-[color:var(--st-text-secondary)]"><span className="text-[color:var(--st-text-muted)]">Type: </span>{entry.resourceType}</p>
              )}
            </div>
          </div>
          <div>
            <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Request Headers</p>
            <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-0.5">
              {entry.request.headers.length > 0 ? entry.request.headers.map((h, i) => (
                <p key={i} className="text-[color:var(--st-text-secondary)] break-all"><span className="text-[color:var(--st-text-muted)] font-mono">{h.name}: </span>{h.value}</p>
              )) : <p className="text-[color:var(--st-text-muted)]">No headers</p>}
            </div>
          </div>
          <div>
            <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Response Headers</p>
            <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-0.5">
              {entry.response.headers.length > 0 ? entry.response.headers.map((h, i) => (
                <p key={i} className="text-[color:var(--st-text-secondary)] break-all"><span className="text-[color:var(--st-text-muted)] font-mono">{h.name}: </span>{h.value}</p>
              )) : <p className="text-[color:var(--st-text-muted)]">No headers</p>}
            </div>
          </div>
        </div>
      )}

      {tab === 'payload' && (
        <div className="space-y-3">
          {/* URL Breakdown */}
          {urlParts && (
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">URL Breakdown</p>
              <div className="bg-[color:var(--st-bg-base)] rounded-lg overflow-hidden divide-y divide-[color:var(--st-border-subtle)]">
                {[
                  { label: 'Scheme', value: urlParts.scheme },
                  { label: 'Host', value: urlParts.host + (urlParts.port ? `:${urlParts.port}` : '') },
                  { label: 'Path', value: urlParts.path },
                  ...(urlParts.fragment ? [{ label: 'Fragment', value: urlParts.fragment }] : []),
                ].map(row => (
                  <div key={row.label} className="flex items-baseline gap-3 px-2.5 py-1.5">
                    <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono w-14 shrink-0">{row.label}</span>
                    <span className="text-[10px] text-[color:var(--st-text-secondary)] font-mono break-all">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Query Parameters */}
          {queryParams.length > 0 && (
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Query Parameters <span className="text-[color:var(--st-text-muted)] opacity-50 font-normal">({queryParams.length})</span></p>
              <div className="bg-[color:var(--st-bg-base)] rounded divide-y divide-[color:var(--st-border-subtle)]">
                {queryParams.map((q, i) => {
                  let decoded = q.value;
                  try { decoded = decodeURIComponent(q.value); } catch { /* keep raw */ }
                  return (
                    <div key={i} className="px-2.5 py-1.5">
                      <span className="text-[10px] text-[color:var(--st-accent)] font-mono font-medium">{decodeURIComponent(q.name)}</span>
                      <p className="text-[10px] text-[color:var(--st-text-secondary)] font-mono mt-0.5 break-all">{decoded}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Cookies */}
          {cookies.length > 0 && (
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Cookies <span className="text-[color:var(--st-text-muted)] opacity-50 font-normal">({cookies.length})</span></p>
              <div className="bg-[color:var(--st-bg-base)] rounded divide-y divide-[color:var(--st-border-subtle)]">
                {cookies.map((c, i) => (
                  <div key={i} className="px-2.5 py-1.5">
                    <span className="text-[10px] text-[color:var(--st-accent)] font-mono font-medium">{c.name}</span>
                    <p className="text-[10px] text-[color:var(--st-text-muted)] font-mono mt-0.5 break-all line-clamp-2">{c.value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Request Body */}
          {hasRequestBody && (() => {
            const { formatted, isJson } = formatBody(entry.request.postData!.text, entry.request.postData!.mimeType || '');
            const sizeKB = entry.request.postData!.text.length / 1024;
            return (
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-[color:var(--st-text-muted)] font-medium">Request Body</p>
                  <span className="text-[9px] font-mono text-[color:var(--st-text-muted)] bg-[color:var(--st-accent-dim)] rounded px-1.5 py-0.5">
                    {entry.request.postData!.mimeType || 'unknown'}
                  </span>
                  <span className="text-[9px] font-mono text-[color:var(--st-text-muted)]">
                    {sizeKB < 1 ? `${entry.request.postData!.text.length} B` : `${sizeKB.toFixed(1)} KB`}
                  </span>
                </div>
                <pre className={cn(
                  'bg-[color:var(--st-bg-base)] rounded-lg p-3 font-mono text-[10px] whitespace-pre-wrap break-all overflow-auto max-h-[400px] leading-relaxed',
                  isJson ? 'text-[color:var(--st-text-secondary)]' : 'text-[color:var(--st-text-secondary)]'
                )}>
                  {formatted}
                </pre>
              </div>
            );
          })()}

          {/* Empty state only if truly nothing */}
          {!hasRequestBody && queryParams.length === 0 && cookies.length === 0 && (
            <div className="py-6 text-center">
              <p className="text-[11px] text-[color:var(--st-text-muted)]">No payload data for this request</p>
            </div>
          )}
        </div>
      )}

      {tab === 'response' && (() => {
        // Parse useful info from response headers
        const getHeader = (name: string) =>
          entry.response.headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';

        const setCookies = entry.response.headers.filter(h => h.name.toLowerCase() === 'set-cookie');
        const cacheControl = getHeader('cache-control');
        const contentType = getHeader('content-type') || responseMime;
        const server = getHeader('server');
        const location = getHeader('location');

        // Security headers check
        const secHeaders = [
          { name: 'Content-Security-Policy', key: 'content-security-policy' },
          { name: 'X-Content-Type-Options', key: 'x-content-type-options' },
          { name: 'X-Frame-Options', key: 'x-frame-options' },
          { name: 'Strict-Transport-Security', key: 'strict-transport-security' },
          { name: 'X-XSS-Protection', key: 'x-xss-protection' },
          { name: 'Referrer-Policy', key: 'referrer-policy' },
          { name: 'Permissions-Policy', key: 'permissions-policy' },
        ].map(sh => ({ ...sh, value: getHeader(sh.key), present: !!getHeader(sh.key) }));

        const secScore = secHeaders.filter(s => s.present).length;

        return (
          <div className="space-y-3">
            {/* Status + size */}
            <div className="flex items-center gap-2">
              <span className={cn('text-[11px] font-mono font-medium', getStatusColor(entry.response.status))}>
                {entry.response.status} {entry.response.statusText}
              </span>
              <span className="text-[9px] font-mono text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-base)] rounded px-1.5 py-0.5">
                {contentType || 'unknown'}
              </span>
              <span className="text-[9px] font-mono text-[color:var(--st-text-muted)]">
                {formatNetSize(entry.response.content?.size || entry.response.bodySize)}
              </span>
            </div>

            {/* Response body if available */}
            {hasResponseBody ? (() => {
              const { formatted, isJson } = formatBody(entry.response.content.text!, responseMime);
              const isHtml = responseMime.includes('html');
              const isImage = responseMime.startsWith('image/');

              if (isImage && entry.response.content.text?.startsWith('data:')) {
                return (
                  <div className="bg-[color:var(--st-bg-base)] rounded p-2">
                    <img src={entry.response.content.text} alt="Response" className="max-w-full max-h-[300px] rounded" />
                  </div>
                );
              }

              return (
                <pre className={cn(
                  'bg-[color:var(--st-bg-base)] rounded p-2 font-mono text-[10px] whitespace-pre-wrap break-all overflow-auto max-h-[500px]',
                  isJson ? 'text-[color:var(--st-text-secondary)]' : isHtml ? 'text-[color:var(--st-text-muted)]' : 'text-[color:var(--st-text-secondary)]'
                )}>
                  {formatted}
                </pre>
              );
            })() : null}

            {/* Redirect target */}
            {location && (
              <div>
                <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Redirect Target</p>
                <div className="bg-[color:var(--st-bg-base)] rounded p-2">
                  <p className="text-[color:var(--st-warning)] font-mono text-[10px] break-all">{location}</p>
                </div>
              </div>
            )}

            {/* Server info */}
            {(server || cacheControl) && (
              <div>
                <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">Server Info</p>
                <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-0.5">
                  {server && (
                    <p className="text-[color:var(--st-text-secondary)] break-all">
                      <span className="text-[color:var(--st-text-muted)] font-mono">Server: </span>
                      <span className="font-mono">{server}</span>
                    </p>
                  )}
                  {cacheControl && (
                    <p className="text-[color:var(--st-text-secondary)] break-all">
                      <span className="text-[color:var(--st-text-muted)] font-mono">Cache: </span>
                      <span className="font-mono">{cacheControl}</span>
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Set-Cookie */}
            {setCookies.length > 0 && (
              <div>
                <p className="text-[color:var(--st-text-muted)] mb-1 font-medium">
                  Set-Cookie <span className="opacity-50 font-normal">({setCookies.length})</span>
                </p>
                <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1">
                  {setCookies.map((c, i) => {
                    const parts = c.value.split(';').map(s => s.trim());
                    const [nameVal, ...attrs] = parts;
                    const hasSecure = attrs.some(a => a.toLowerCase() === 'secure');
                    const hasHttpOnly = attrs.some(a => a.toLowerCase() === 'httponly');
                    const hasSameSite = attrs.some(a => a.toLowerCase().startsWith('samesite'));
                    return (
                      <div key={i} className="text-[10px] break-all">
                        <span className="text-[color:var(--st-warning)] font-mono">{nameVal}</span>
                        <div className="flex gap-1 mt-0.5">
                          {hasSecure && <span className="text-[8px] px-1 py-px rounded bg-[color:var(--st-success)]/10 text-[color:var(--st-success)]">Secure</span>}
                          {hasHttpOnly && <span className="text-[8px] px-1 py-px rounded bg-[color:var(--st-accent)]/10 text-[color:var(--st-accent)]">HttpOnly</span>}
                          {hasSameSite && <span className="text-[8px] px-1 py-px rounded bg-[color:var(--st-purple)]/10 text-[color:var(--st-purple)]">SameSite</span>}
                          {!hasSecure && <span className="text-[8px] px-1 py-px rounded bg-[color:var(--st-danger)]/10 text-[color:var(--st-danger)]">No Secure</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Security Headers */}
            <div>
              <div className="flex items-center gap-2 mb-1">
                <p className="text-[color:var(--st-text-muted)] font-medium">Security Headers</p>
                <span className={cn(
                  'text-[9px] font-mono px-1.5 py-0.5 rounded',
                  secScore >= 5 ? 'bg-[color:var(--st-success)]/10 text-[color:var(--st-success)]' :
                  secScore >= 3 ? 'bg-[color:var(--st-warning)]/10 text-[color:var(--st-warning)]' :
                  'bg-[color:var(--st-danger)]/10 text-[color:var(--st-danger)]'
                )}>
                  {secScore}/{secHeaders.length}
                </span>
              </div>
              <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-0.5">
                {secHeaders.map(sh => (
                  <div key={sh.key} className="flex items-start gap-2 text-[10px]">
                    <span className={cn('w-2 h-2 rounded-full mt-0.5 shrink-0', sh.present ? 'bg-[color:var(--st-success)]' : 'bg-[color:var(--st-border)]')} />
                    <span className={cn('font-mono', sh.present ? 'text-[color:var(--st-text-secondary)]' : 'text-[color:var(--st-text-muted)] opacity-40')}>
                      {sh.name}
                    </span>
                    {sh.present && sh.value.length < 80 && (
                      <span className="text-[color:var(--st-text-muted)] font-mono truncate ml-auto">{sh.value}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        );
      })()}

      {tab === 'timing' && (() => {
        const totalTime = entry.time || 0;
        const waitTime = entry.timings.wait > 0 ? entry.timings.wait : totalTime;

        return (
          <div className="space-y-3">
            {/* Total time bar */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[color:var(--st-text-muted)] font-medium">Total Duration</p>
                <span className="text-[13px] font-mono font-bold text-[color:var(--st-text-primary)]">
                  {totalTime > 0 ? `${Math.round(totalTime)} ms` : '-'}
                </span>
              </div>
              {totalTime > 0 && (
                <div className="h-3 bg-[color:var(--st-bg-panel)] rounded overflow-hidden">
                  <div className="h-full rounded bg-[color:var(--st-accent)]" style={{ width: '100%' }} />
                </div>
              )}
            </div>

            {/* Breakdown */}
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1.5 font-medium">Breakdown</p>
              <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1.5">
                {[
                  { label: 'Blocked', value: entry.timings.blocked, color: 'bg-gray-500' },
                  { label: 'DNS', value: entry.timings.dns, color: 'bg-cyan-500' },
                  { label: 'Connect', value: entry.timings.connect, color: 'bg-orange-500' },
                  { label: 'SSL/TLS', value: entry.timings.ssl, color: 'bg-purple-500' },
                  { label: 'Send', value: entry.timings.send, color: 'bg-green-500' },
                  { label: 'Wait (TTFB)', value: waitTime, color: 'bg-blue-500' },
                  { label: 'Receive', value: entry.timings.receive, color: 'bg-yellow-500' },
                ].map((t) => (
                  <div key={t.label} className="flex items-center gap-2">
                    <span className="w-20 text-[color:var(--st-text-muted)] shrink-0">{t.label}</span>
                    <div className="flex-1 h-2 bg-[color:var(--st-bg-panel)] rounded overflow-hidden">
                      {t.value > 0 && (
                        <div className={cn('h-full rounded', t.color)} style={{ width: `${Math.min(100, (t.value / Math.max(totalTime, 1)) * 100)}%` }} />
                      )}
                    </div>
                    <span className="w-16 text-right text-[color:var(--st-text-muted)] shrink-0 font-mono">{t.value > 0 ? `${Math.round(t.value)} ms` : '-'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Size info */}
            <div>
              <p className="text-[color:var(--st-text-muted)] mb-1.5 font-medium">Transfer</p>
              <div className="bg-[color:var(--st-bg-base)] rounded p-2 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--st-text-muted)]">Response Size</span>
                  <span className="font-mono text-[color:var(--st-text-secondary)]">{formatNetSize(entry.response.content?.size || entry.response.bodySize)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--st-text-muted)]">MIME Type</span>
                  <span className="font-mono text-[color:var(--st-text-secondary)]">{entry.response.content?.mimeType || '-'}</span>
                </div>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// WhitelistEditor
// ═══════════════════════════════════════════════════════

function WhitelistEditor({ whitelist, onSave, onClose }: {
  whitelist: DomainWhitelist;
  onSave: (wl: DomainWhitelist) => void;
  onClose: () => void;
}) {
  const [domains, setDomains] = useState(whitelist.domains.join('\n'));
  const [patterns, setPatterns] = useState(whitelist.patterns.join('\n'));
  const [useBuiltIn, setUseBuiltIn] = useState(whitelist.useBuiltIn);

  const [saveError, setSaveError] = useState<string | null>(null);

  const handleSave = async () => {
    setSaveError(null);
    const wl: DomainWhitelist = {
      domains: domains.split('\n').map(s => s.trim()).filter(Boolean),
      patterns: patterns.split('\n').map(s => s.trim()).filter(Boolean),
      useBuiltIn,
    };
    const result = await window.shieldtier.config.setWhitelist(wl);
    if (result && !result.success) {
      setSaveError(result.error || 'Failed to save whitelist');
      return;
    }
    onSave(wl);
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="w-[500px] max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Domain Whitelist</DialogTitle>
        </DialogHeader>

        <ScrollArea className="flex-1 pr-2">
          <div className="space-y-4 py-2">
            {/* Built-in toggle */}
            <label className="flex items-center gap-2 text-xs text-[color:var(--st-text-secondary)] cursor-pointer">
              <input
                type="checkbox"
                checked={useBuiltIn}
                onChange={e => setUseBuiltIn(e.target.checked)}
                className="rounded border-gray-600"
              />
              Use built-in CDN whitelist
            </label>
            {useBuiltIn && (
              <div className="bg-[color:var(--st-bg-base)] rounded-lg p-2 text-[10px] text-[color:var(--st-text-muted)] space-y-0.5 font-mono">
                {BUILT_IN_PATTERNS.map(p => (
                  <div key={p}>{p}</div>
                ))}
              </div>
            )}

            {/* Custom domains */}
            <div>
              <label className="text-xs text-[color:var(--st-text-muted)] block mb-1.5">Custom Domains (one per line)</label>
              <textarea
                value={domains}
                onChange={e => setDomains(e.target.value)}
                placeholder={"fonts.googleapis.com\ncdn.example.com"}
                rows={4}
                className="w-full bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-lg px-3 py-2 text-xs text-[color:var(--st-text-primary)] outline-none focus:border-[color:var(--st-accent)] placeholder-[color:var(--st-text-muted)] resize-none font-mono"
              />
            </div>

            {/* Wildcard patterns */}
            <div>
              <label className="text-xs text-[color:var(--st-text-muted)] block mb-1.5">Wildcard Patterns (one per line)</label>
              <textarea
                value={patterns}
                onChange={e => setPatterns(e.target.value)}
                placeholder={"*.cdn.example.com\n*.analytics.provider.net"}
                rows={3}
                className="w-full bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-lg px-3 py-2 text-xs text-[color:var(--st-text-primary)] outline-none focus:border-[color:var(--st-accent)] placeholder-[color:var(--st-text-muted)] resize-none font-mono"
              />
              <p className="text-[10px] text-[color:var(--st-text-muted)] mt-1">Use *.domain.com to match all subdomains</p>
            </div>
          </div>
        </ScrollArea>

        <DialogFooter className="pt-3 border-t border-[color:var(--st-border)]">
          {saveError && <span className="text-[10px] text-[color:var(--st-danger)] mr-2">{saveError}</span>}
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSave}>
            Save Whitelist
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
