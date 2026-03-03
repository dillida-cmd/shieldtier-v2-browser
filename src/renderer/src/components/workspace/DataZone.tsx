import { useCallback, type ReactNode } from 'react';
import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { useStore, type BottomTab } from '../../store';
import { NetworkPanel } from '../panels/NetworkPanel';
import { IOCPanel } from '../panels/IOCPanel';
import { ScreenshotsPanel } from '../panels/ScreenshotsPanel';
import { FilesPanel } from '../panels/FilesPanel';
import { SandboxPanel } from '../panels/SandboxPanel';
import { FindingsPanel } from '../panels/FindingsPanel';
import { MITREPanel } from '../panels/MITREPanel';
import { ActivityPanel } from '../panels/ActivityPanel';
import { TimelinePanel } from '../panels/TimelinePanel';
import { ProcessPanel } from '../panels/ProcessPanel';

interface TabDef { id: BottomTab; label: string; group: number; }

const TABS: TabDef[] = [
  { id: 'network', label: 'Network', group: 0 },
  { id: 'ioc', label: 'IOC', group: 0 },
  { id: 'screenshots', label: 'Screenshots', group: 0 },
  { id: 'files', label: 'Files', group: 0 },
  { id: 'sandbox', label: 'Sandbox', group: 1 },
  { id: 'findings', label: 'Findings', group: 1 },
  { id: 'mitre', label: 'MITRE', group: 1 },
  { id: 'activity', label: 'Activity', group: 2 },
  { id: 'timeline', label: 'Timeline', group: 2 },
  { id: 'process', label: 'Process', group: 2 },
];

const PANEL_MAP: Record<BottomTab, () => ReactNode> = {
  network: () => <NetworkPanel />,
  ioc: () => <IOCPanel />,
  screenshots: () => <ScreenshotsPanel />,
  files: () => <FilesPanel />,
  sandbox: () => <SandboxPanel />,
  findings: () => <FindingsPanel />,
  mitre: () => <MITREPanel />,
  activity: () => <ActivityPanel />,
  timeline: () => <TimelinePanel />,
  process: () => <ProcessPanel />,
};

export function DataZone() {
  const { bottomTabs, bottomPrimaryTab, setBottomPrimaryTab } = useStore();

  const onTabClick = useCallback((tabId: BottomTab) => {
    setBottomPrimaryTab(tabId);
  }, [setBottomPrimaryTab]);

  let prevGroup = -1;

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-panel)] border-t border-[var(--st-border)]">
      <div className="flex items-center h-7 px-2 gap-0.5 border-b border-[var(--st-border)] flex-shrink-0 overflow-x-auto">
        {TABS.map((tab) => {
          const showSep = prevGroup >= 0 && tab.group !== prevGroup;
          prevGroup = tab.group;
          const isActive = bottomTabs.includes(tab.id);
          const isPrimary = tab.id === bottomPrimaryTab;

          return (
            <span key={tab.id} className="flex items-center">
              {showSep && <span className="text-[var(--st-border)] mx-1 select-none text-[10px]">|</span>}
              <button
                onClick={() => onTabClick(tab.id)}
                className={cn(
                  'px-2 py-1 rounded text-[10px] font-medium border-none cursor-pointer transition-colors whitespace-nowrap flex items-center gap-1',
                  isPrimary
                    ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)]'
                    : isActive
                      ? 'bg-transparent text-[var(--st-text-label)]'
                      : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-label)] hover:bg-[var(--st-bg-hover)]',
                )}
              >
                {tab.label}
                {isActive && <CountBadge count={0} color="blue" />}
              </button>
            </span>
          );
        })}
      </div>
      <div className="flex-1 flex overflow-hidden">
        {bottomTabs.map((tabId, i) => (
          <div key={tabId} className={cn('flex-1 min-w-0 overflow-hidden', i < bottomTabs.length - 1 && 'border-r border-[var(--st-border)]')}>
            {PANEL_MAP[tabId]()}
          </div>
        ))}
      </div>
    </div>
  );
}
