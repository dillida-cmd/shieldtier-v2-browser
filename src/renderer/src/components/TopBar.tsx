import React from 'react';
import type { ProxyConfig } from '../types';
import { cn } from '../lib/utils';

interface TopBarProps {
  proxyConfig: ProxyConfig | null;
  status: string;
  analystName?: string;
  chatOpen?: boolean;
  chatUnread?: number;
  onConfigureProxy: () => void;
  onOpenSettings?: () => void;
  onToggleChat?: () => void;
}

export function TopBar({ proxyConfig, status, analystName, chatOpen, chatUnread, onConfigureProxy, onOpenSettings, onToggleChat }: TopBarProps) {
  return (
    <div
      className="flex items-center h-11 pr-3 border-b border-[color:var(--st-border)] select-none"
      style={{ background: 'var(--st-bg-toolbar)', WebkitAppRegion: 'drag', paddingLeft: '8px' } as React.CSSProperties}
    >
      {/* Left: Logo + Welcome */}
      <div className="flex items-center gap-3" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
        <span className="font-semibold text-[13px] tracking-wide text-gradient-brand">SHIELDTIER</span>
        <span className="w-px h-4 bg-[color:var(--st-border)]" />
        {analystName ? (
          <div className="flex items-baseline gap-1.5">
            <span className="text-[12px] text-[color:var(--st-text-muted)]">Welcome,</span>
            <span className="text-[15px] font-semibold text-[color:var(--st-text-primary)]">{analystName}</span>
          </div>
        ) : (
          <span className="text-[color:var(--st-text-secondary)] text-[12px]">SOC Browser</span>
        )}
      </div>

      {/* Center: spacer */}
      <div className="flex-1" />

      {/* Right: Proxy + Chat + Settings + Avatar */}
      <div className="flex items-center gap-1.5" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
        <button
          type="button"
          onClick={onConfigureProxy}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] text-[color:var(--st-text-secondary)] hover:text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-border-subtle)] border border-[color:var(--st-border)] transition-colors cursor-pointer"
        >
          <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', 'bg-[color:var(--st-success)]')} />
          <span>Connected:</span>
          <span className="font-semibold">{proxyConfig ? proxyConfig.type.toUpperCase() : 'DIRECT'}</span>
        </button>

        {/* Toolbar divider */}
        <span className="w-px h-5 bg-[color:var(--st-border)] mx-0.5" />

        {/* Chat toggle */}
        {onToggleChat && (
          <button
            type="button"
            onClick={onToggleChat}
            aria-label={`Toggle Chat${(chatUnread || 0) > 0 ? ` (${chatUnread} unread)` : ''}`}
            aria-pressed={chatOpen}
            title="Toggle Chat"
            className={cn(
              'relative w-7 h-7 rounded-md flex items-center justify-center transition-colors',
              chatOpen
                ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]'
                : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]',
            )}
          >
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
              <path d="M2 3a1 1 0 011-1h10a1 1 0 011 1v7a1 1 0 01-1 1H5l-3 3V3z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
            </svg>
            {(chatUnread || 0) > 0 && (
              <span className="absolute -top-0.5 -right-0.5 text-[8px] bg-[color:var(--st-danger)] text-white px-1 rounded-full min-w-[12px] text-center leading-[12px]">
                {chatUnread}
              </span>
            )}
          </button>
        )}
        {/* Settings */}
        {onOpenSettings && (
          <button
            type="button"
            onClick={onOpenSettings}
            aria-label="Settings"
            title="Settings"
            className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}
