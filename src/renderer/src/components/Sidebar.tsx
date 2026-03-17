import React from 'react';
import type { InvestigationSession } from '../types';
import { ScrollArea } from './ui/scroll-area';
import { cn } from '../lib/utils';

interface SidebarProps {
  sessions: InvestigationSession[];
  activeSessionId: string | null;
  onSelectSession: (id: string) => void;
  onDestroySession: (id: string) => void;
  onNewSession: () => void;
}

export function Sidebar({ sessions, activeSessionId, onSelectSession, onDestroySession, onNewSession }: SidebarProps) {
  return (
    <div
      className="w-52 flex flex-col border-r border-[color:var(--st-border)] shrink-0"
      style={{ background: 'var(--st-bg-panel)' }}
    >
      {/* Header — macOS source list style */}
      <div className="px-3 pt-3 pb-2">
        <h3 className="text-[11px] font-semibold text-[color:var(--st-text-muted)] uppercase tracking-widest">
          Investigations
        </h3>
      </div>

      {/* Session list — source list pattern */}
      <ScrollArea className="flex-1">
        <div className="px-2 space-y-0.5" role="list" aria-label="Investigation sessions">
          {sessions.length === 0 ? (
            <p className="text-[11px] text-[color:var(--st-text-muted)] p-3 text-center leading-relaxed">
              No active sessions.<br />
              Click below to start.
            </p>
          ) : (
            sessions.map(session => {
              const isActive = session.id === activeSessionId;
              return (
                <div key={session.id} role="listitem" className="group relative">
                  <button
                    type="button"
                    className={cn(
                      'w-full text-left px-2.5 py-1.5 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[color:var(--st-accent)]',
                      isActive
                        ? 'bg-[color:var(--st-accent)] text-white'
                        : 'text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-border-subtle)]',
                    )}
                    onClick={() => onSelectSession(session.id)}
                    aria-current={isActive ? 'true' : undefined}
                  >
                    <div className="flex items-baseline gap-1.5 text-[12px] font-medium truncate">
                      <span className={cn(
                        'text-[10px] font-mono shrink-0',
                        isActive ? 'text-white/70' : 'text-[color:var(--st-accent)]'
                      )}>
                        {session.caseId}
                      </span>
                      <span className="truncate">
                        {session.caseName || session.url || `Session ${session.id.slice(0, 6)}`}
                      </span>
                    </div>
                    <div className={cn(
                      'text-[10px] font-mono mt-0.5',
                      isActive ? 'text-white/50' : 'text-[color:var(--st-text-muted)]'
                    )}>
                      {new Date(session.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </button>
                  {/* Destroy button — hover reveal */}
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onDestroySession(session.id); }}
                    className={cn(
                      'absolute right-1 top-1/2 -translate-y-1/2 w-5 h-5 rounded flex items-center justify-center transition-opacity',
                      'opacity-0 group-hover:opacity-100 focus-visible:opacity-100',
                      isActive
                        ? 'text-white/60 hover:text-white hover:bg-white/10'
                        : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-danger)] hover:bg-[color:var(--st-danger-dim)]'
                    )}
                    aria-label={`Destroy session ${session.caseId || session.id.slice(0, 8)}`}
                    title="Destroy session"
                  >
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                  </button>
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>

      {/* Footer */}
      <div className="p-2 border-t border-[color:var(--st-border)]">
        <button
          type="button"
          onClick={onNewSession}
          className="w-full py-1.5 rounded-md text-[12px] font-medium text-[color:var(--st-text-secondary)] hover:text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-border-subtle)] border border-[color:var(--st-border)] transition-colors"
        >
          + New Investigation
        </button>
      </div>
    </div>
  );
}
