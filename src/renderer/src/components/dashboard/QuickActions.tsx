import React from 'react';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';

interface QuickActionsProps {
  hasProxy: boolean;
  onNewSession: () => void;
  onConfigureProxy: () => void;
  onOpenSettings: () => void;
}

export function QuickActions({ hasProxy, onNewSession, onConfigureProxy, onOpenSettings }: QuickActionsProps) {
  return (
    <div>
      <h3 className="text-xs font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-3">Quick Actions</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {/* New Investigation */}
        <button
          onClick={hasProxy ? onNewSession : onConfigureProxy}
          className="glass rounded-xl border border-[color:var(--st-accent)]/20 p-4 text-left transition-all hover:border-[color:var(--st-accent)]/40 hover:shadow-[0_0_20px_var(--st-accent-glow)] hover:scale-[1.02] active:scale-100 group"
          {...(!hasProxy ? { 'aria-describedby': 'proxy-warning' } : {})}
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[color:var(--st-accent)]/10 flex items-center justify-center shrink-0">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-[color:var(--st-accent)]">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>
              </svg>
            </div>
            <div className="min-w-0">
              <div className="text-sm font-medium text-[color:var(--st-text-primary)] group-hover:text-[color:var(--st-accent)] transition-colors">New Investigation</div>
              <div className="text-xs text-[color:var(--st-text-muted)] mt-0.5">Start an isolated browser session</div>
              {!hasProxy && (
                <div id="proxy-warning" className="text-[10px] text-amber-400/70 mt-1">Configure proxy first</div>
              )}
            </div>
          </div>
        </button>

        {/* Open Settings */}
        <button
          onClick={onOpenSettings}
          className="glass rounded-xl border p-4 text-left transition-all hover:border-[color:var(--st-border)] hover:bg-[color:var(--st-accent-dim)] hover:scale-[1.02] active:scale-100 group"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[color:var(--st-accent-dim)] flex items-center justify-center shrink-0">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-[color:var(--st-text-muted)]">
                <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
              </svg>
            </div>
            <div className="min-w-0">
              <div className="text-sm font-medium text-[color:var(--st-text-primary)] group-hover:text-[color:var(--st-text-primary)] transition-colors">Open Settings</div>
              <div className="text-xs text-[color:var(--st-text-muted)] mt-0.5">API keys, proxy, appearance</div>
            </div>
          </div>
        </button>
      </div>
    </div>
  );
}
