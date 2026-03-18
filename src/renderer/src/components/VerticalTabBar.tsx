import React from 'react';
import { Badge } from './ui/badge';
import { cn } from '../lib/utils';

export type PanelTab = 'browser' | 'network' | 'screenshots' | 'timeline' | 'analysis' | 'sandbox' | 'vm-sandbox' | 'files' | 'email' | 'logs' | 'mitre' | 'threatfeed';

interface VerticalTabBarProps {
  activePanel: PanelTab;
  onSelectPanel: (panel: PanelTab) => void;
  badges: Partial<Record<PanelTab, number>>;
  captureEnabled: boolean;
  onOpenReport: () => void;
}

interface TabDef {
  id: PanelTab;
  label: string;
  badgeVariant: 'default' | 'purple' | 'destructive';
  icon: React.ReactNode;
}

const TABS: TabDef[] = [
  { id: 'browser', label: 'Browser', badgeVariant: 'default', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> },
  { id: 'network', label: 'Network', badgeVariant: 'default', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> },
  { id: 'screenshots', label: 'Screenshots', badgeVariant: 'default', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg> },
  { id: 'timeline', label: 'Timeline', badgeVariant: 'default', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
  { id: 'analysis', label: 'Analysis', badgeVariant: 'purple', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> },
  { id: 'sandbox', label: 'Sandbox', badgeVariant: 'destructive', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5z"/><line x1="16" y1="8" x2="2" y2="22"/><line x1="17.5" y1="15" x2="9" y2="15"/></svg> },
  { id: 'vm-sandbox', label: 'VM Sandbox', badgeVariant: 'destructive', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> },
  { id: 'files', label: 'Files', badgeVariant: 'destructive', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg> },
  { id: 'email', label: 'Email', badgeVariant: 'purple', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg> },
  { id: 'logs', label: 'Logs', badgeVariant: 'purple', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg> },
  { id: 'mitre', label: 'MITRE', badgeVariant: 'purple', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> },
  { id: 'threatfeed', label: 'Threat Feeds', badgeVariant: 'destructive', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg> },
];

const GROUP_STARTS = new Set<PanelTab>(['analysis', 'mitre']);

export function VerticalTabBar({ activePanel, onSelectPanel, badges, captureEnabled, onOpenReport }: VerticalTabBarProps) {
  return (
      <div
        className="w-11 border-r border-[color:var(--st-border)] flex flex-col items-center py-1.5 shrink-0"
        style={{ background: 'var(--st-bg-panel)' }}
      >
        {/* Panel tabs — using native title instead of Radix Tooltip to avoid double-click */}
        <div className="flex-1 flex flex-col items-center gap-px" role="tablist" aria-label="Panel navigation">
          {TABS.map(tab => {
            const isActive = activePanel === tab.id;
            const badge = badges[tab.id];
            const titleText = badge && badge > 0 ? `${tab.label} (${badge})` : tab.label;
            return (
              <React.Fragment key={tab.id}>
                {GROUP_STARTS.has(tab.id) && (
                  <div className="w-5 h-px bg-[color:var(--st-border)] my-1" />
                )}
                    <button
                      type="button"
                      role="tab"
                      aria-selected={isActive}
                      aria-label={tab.label}
                      title={titleText}
                      onClick={() => onSelectPanel(tab.id)}
                      className={cn(
                        'relative w-8 h-8 rounded-md flex items-center justify-center transition-colors cursor-pointer',
                        isActive
                          ? 'text-[color:var(--st-accent)]'
                          : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]',
                      )}
                    >
                      {/* Active indicator — thin left bar */}
                      {isActive && (
                        <div className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r-full bg-[color:var(--st-accent)]" />
                      )}
                      {tab.icon}
                      {/* Badge */}
                      {badge !== undefined && badge > 0 && (
                        <Badge
                          variant={tab.badgeVariant}
                          size="sm"
                          className="absolute -top-0.5 -right-1 px-0.5 min-w-[12px] text-center leading-[12px] text-[9px]"
                        >
                          {badge > 99 ? '99+' : badge}
                        </Badge>
                      )}
                    </button>
              </React.Fragment>
            );
          })}
        </div>

        {/* Bottom section */}
        <div className="flex flex-col items-center gap-0.5 pt-1.5 border-t border-[color:var(--st-border)]">
          {/* REC indicator */}
          {captureEnabled && (
            <div className="flex items-center justify-center w-8 h-5" title="Recording" role="status" aria-live="polite" aria-label="Network capture recording">
              <span className="w-1.5 h-1.5 rounded-full bg-[color:var(--st-danger)] animate-pulse" aria-hidden="true" />
              <span className="text-[8px] text-[color:var(--st-danger)] ml-0.5 font-bold">REC</span>
            </div>
          )}
          {/* Report button */}
              <button
                type="button"
                onClick={onOpenReport}
                title="Generate Report"
                className="w-8 h-8 rounded-md flex items-center justify-center text-[color:var(--st-purple)] hover:bg-[color:var(--st-purple-dim)] transition-colors cursor-pointer"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                  <line x1="16" y1="13" x2="8" y2="13"/>
                  <line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
              </button>
        </div>
      </div>
  );
}
