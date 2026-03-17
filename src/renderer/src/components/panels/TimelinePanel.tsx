/**
 * TimelinePanel — Investigation timeline display.
 * macOS Instruments-inspired event list.
 */

import React from 'react';
import { cn } from '../../lib/utils';
import { ScrollArea } from '../ui/scroll-area';
import { Badge } from '../ui/badge';
import type { TimelineEvent } from './panel-types';

export function TimelinePanel({ events }: { events: TimelineEvent[] }) {
  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <span className="text-[11px] font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider">Timeline</span>
        <span className="w-px h-3 bg-[color:var(--st-border)]" />
        <span className="text-[11px] text-[color:var(--st-text-muted)]">{events.length} events</span>
      </div>
      {/* Event list */}
      <ScrollArea className="flex-1">
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[11px] text-[color:var(--st-text-muted)]">
            No timeline events yet. Start browsing to generate events.
          </div>
        ) : (
          <div className="divide-y divide-[color:var(--st-border)]">
            {events.map((e, i) => (
              <div key={`${e.time}-${e.event}-${i}`} className="flex items-start gap-3 px-3 py-2 hover:bg-[color:var(--st-border-subtle)] transition-colors">
                <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono w-[60px] shrink-0 pt-0.5 text-right">{e.time}</span>
                <div className={cn(
                  'w-1.5 h-1.5 rounded-full mt-1.5 shrink-0',
                  e.type === 'danger' ? 'bg-[color:var(--st-danger)]' : e.type === 'warning' ? 'bg-[color:var(--st-warning)]' : 'bg-[color:var(--st-info)]'
                )} />
                <div className="min-w-0 flex-1">
                  <p className="text-[12px] text-[color:var(--st-text-primary)]">{e.event}</p>
                  <p className="text-[10px] text-[color:var(--st-text-muted)] truncate font-mono" title={e.detail}>{e.detail}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
