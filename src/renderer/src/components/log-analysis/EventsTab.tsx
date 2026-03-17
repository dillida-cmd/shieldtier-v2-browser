// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Events Tab
// ---------------------------------------------------------------------------

import React from 'react';
import type { Severity, NormalizedEvent } from './log-analysis-types';
import { EVENTS_PER_PAGE, getSeverityBadge, formatTimestamp, truncate } from './log-analysis-utils';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../ui/table';

interface EventsTabProps {
  events: NormalizedEvent[];
  filteredCount: number;
  totalCount: number;
  search: string;
  onSearchChange: (s: string) => void;
  severityFilter: string | null;
  onSeverityFilterChange: (s: string | null) => void;
  page: number;
  totalPages: number;
  onPageChange: (p: number) => void;
  expandedIdx: number | null;
  onToggleExpand: (idx: number | null) => void;
}

export function EventsTab({
  events,
  filteredCount,
  totalCount,
  search,
  onSearchChange,
  severityFilter,
  onSeverityFilterChange,
  page,
  totalPages,
  onPageChange,
  expandedIdx,
  onToggleExpand,
}: EventsTabProps) {
  return (
    <div className="space-y-3">
      {/* Search bar */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <svg
            width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="2" className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[color:var(--st-text-muted)]"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder="Search events..."
            className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded-md pl-8 pr-3 py-1.5 text-xs text-[color:var(--st-text-primary)] focus:border-blue-500/50 outline-none placeholder-[color:var(--st-text-muted)]"
          />
        </div>
        <span className="text-[10px] text-[color:var(--st-text-muted)] whitespace-nowrap">
          {filteredCount.toLocaleString()} / {totalCount.toLocaleString()}
        </span>
      </div>

      {/* Severity filter chips */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <button
          onClick={() => onSeverityFilterChange(null)}
          className={`px-2 py-0.5 rounded-full text-[10px] transition-colors ${
            !severityFilter
              ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-primary)]'
              : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
          }`}
        >
          All
        </button>
        {(['info', 'low', 'medium', 'high', 'critical'] as Severity[]).map(sev => (
          <button
            key={sev}
            onClick={() => onSeverityFilterChange(severityFilter === sev ? null : sev)}
            className={`px-2 py-0.5 rounded-full text-[10px] capitalize transition-colors border ${
              severityFilter === sev
                ? getSeverityBadge(sev) + ' border-current'
                : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] border-transparent'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Events table */}
      <div className="rounded-lg glass-light border overflow-hidden">
        <table className="w-full text-[11px]">
          <thead className="bg-[color:var(--st-accent-dim)]">
            <tr>
              <th className="text-left px-3 py-1.5 text-[color:var(--st-text-muted)] font-medium w-36">Timestamp</th>
              <th className="text-left px-2 py-1.5 text-[color:var(--st-text-muted)] font-medium w-16">Severity</th>
              <th className="text-left px-2 py-1.5 text-[color:var(--st-text-muted)] font-medium w-24">Category</th>
              <th className="text-left px-2 py-1.5 text-[color:var(--st-text-muted)] font-medium w-32">Type</th>
              <th className="text-left px-2 py-1.5 text-[color:var(--st-text-muted)] font-medium">Message</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt, i) => {
              const globalIdx = page * EVENTS_PER_PAGE + i;
              const isExpanded = expandedIdx === globalIdx;
              return (
                <React.Fragment key={globalIdx}>
                  <tr
                    onClick={() => onToggleExpand(isExpanded ? null : globalIdx)}
                    className="border-t border-[color:var(--st-border-subtle)] cursor-pointer hover:bg-[color:var(--st-accent-dim)] transition-colors"
                  >
                    <td className="px-3 py-1.5 text-[color:var(--st-text-muted)] font-mono whitespace-nowrap">
                      {formatTimestamp(evt.timestamp)}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${getSeverityBadge(evt.severity)}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="px-1.5 py-0.5 rounded bg-gray-500/10 text-[color:var(--st-text-muted)] text-[9px]">
                        {evt.category}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 text-[color:var(--st-text-secondary)] font-mono truncate max-w-[128px]">
                      {evt.eventType}
                    </td>
                    <td className="px-2 py-1.5 text-[color:var(--st-text-muted)] truncate max-w-xs">
                      {truncate(evt.message, 120)}
                    </td>
                  </tr>
                  {/* Expanded row */}
                  {isExpanded && (
                    <tr className="border-t border-[color:var(--st-border-subtle)]">
                      <td colSpan={5} className="px-3 py-3 bg-[color:var(--st-bg-base)]">
                        {/* Raw line */}
                        <div className="mb-2">
                          <span className="text-[9px] text-[color:var(--st-text-muted)] uppercase tracking-wider">Raw</span>
                          <pre className="mt-0.5 text-[10px] text-[color:var(--st-text-muted)] font-mono bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-2 max-h-32 overflow-auto whitespace-pre-wrap break-all">
                            {evt.raw}
                          </pre>
                        </div>
                        {/* Metadata key-value pairs */}
                        {Object.keys(evt.metadata).length > 0 && (
                          <div>
                            <span className="text-[9px] text-[color:var(--st-text-muted)] uppercase tracking-wider">Metadata</span>
                            <div className="mt-0.5 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px]">
                              {Object.entries(evt.metadata).map(([key, val]) => (
                                <div key={key} className="flex gap-2">
                                  <span className="text-blue-400 font-mono">{key}:</span>
                                  <span className="text-[color:var(--st-text-muted)] truncate">
                                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center py-8 text-[color:var(--st-text-muted)] text-xs">
                  No events match the current filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => onPageChange(Math.max(0, page - 1))}
            disabled={page === 0}
            className="px-2 py-1 text-xs text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] disabled:text-[color:var(--st-text-muted)] disabled:cursor-not-allowed transition-colors"
          >
            Prev
          </button>
          <span className="text-[10px] text-[color:var(--st-text-muted)]">
            Page {page + 1} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="px-2 py-1 text-xs text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] disabled:text-[color:var(--st-text-muted)] disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
