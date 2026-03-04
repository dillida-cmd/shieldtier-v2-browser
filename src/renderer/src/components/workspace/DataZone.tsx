import { useCallback, useMemo, type ReactNode } from 'react';
import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { Separator } from '../ui/Separator';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/Tooltip';
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
import type { HarLog, Finding } from '../../ipc/types';

interface TabDef { id: BottomTab; label: string; group: number; desc: string; }

const TABS: TabDef[] = [
  { id: 'network', label: 'Network', group: 0, desc: 'HTTP request/response capture' },
  { id: 'ioc', label: 'IOC', group: 0, desc: 'Indicators of compromise' },
  { id: 'screenshots', label: 'Screenshots', group: 0, desc: 'VM screen captures' },
  { id: 'files', label: 'Files', group: 0, desc: 'Captured/dropped files' },
  { id: 'sandbox', label: 'Sandbox', group: 1, desc: 'VM sandbox summary' },
  { id: 'findings', label: 'Findings', group: 1, desc: 'All detection findings' },
  { id: 'mitre', label: 'MITRE', group: 1, desc: 'ATT&CK technique mapping' },
  { id: 'activity', label: 'Activity', group: 2, desc: 'Live event feed' },
  { id: 'timeline', label: 'Timeline', group: 2, desc: 'Chronological event timeline' },
  { id: 'process', label: 'Process', group: 2, desc: 'Process tree from VM' },
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

function countNetworkEntries(har: string): number {
  if (!har) return 0;
  try {
    const parsed: HarLog = JSON.parse(har);
    return parsed.log.entries.length;
  } catch {
    return 0;
  }
}

function countIOCs(findings: Finding[]): number {
  const seen = new Set<string>();
  for (const f of findings) {
    const meta = f.metadata;
    if (typeof meta.domain === 'string') seen.add(meta.domain);
    if (typeof meta.destination === 'string') seen.add(meta.destination);
    if (typeof meta.path === 'string' && (meta.path as string).match(/^https?:\/\//)) seen.add(meta.path as string);
  }
  return seen.size;
}

function countMitre(findings: Finding[]): number {
  const ids = new Set<string>();
  for (const f of findings) {
    const id = String(f.metadata.mitre ?? '');
    if (id) ids.add(id);
  }
  return ids.size;
}

function countProcessNodes(nodes: Array<{ children: Array<unknown> }>): number {
  let count = 0;
  const stack = [...nodes];
  while (stack.length) {
    const node = stack.pop()!;
    count++;
    stack.push(...(node.children as typeof nodes));
  }
  return count;
}

export function DataZone() {
  const {
    bottomTabs, bottomPrimaryTab, setBottomPrimaryTab,
    captureData, analysisResult, vmFindings, vmEvents, vmProcessTree, screenshots, capturedFiles,
  } = useStore();

  const onTabClick = useCallback((tabId: BottomTab) => {
    setBottomPrimaryTab(tabId);
  }, [setBottomPrimaryTab]);

  const allFindings = useMemo(() => {
    return [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
  }, [analysisResult, vmFindings]);

  const tabCounts = useMemo<Record<BottomTab, number>>(() => ({
    network: countNetworkEntries(captureData?.har ?? ''),
    ioc: countIOCs(allFindings),
    screenshots: screenshots.length,
    files: capturedFiles.length,
    sandbox: vmEvents.length,
    findings: allFindings.length,
    mitre: countMitre(allFindings),
    activity: allFindings.length,
    timeline: vmEvents.length,
    process: countProcessNodes(vmProcessTree),
  }), [captureData, allFindings, vmEvents, vmProcessTree, screenshots, capturedFiles]);

  const tabsWithSep = useMemo(() => {
    let prev = -1;
    return TABS.map((tab) => {
      const showSep = prev >= 0 && tab.group !== prev;
      prev = tab.group;
      return { ...tab, showSep };
    });
  }, []);

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-panel)] border-t border-[var(--st-border)]">
      <div className="flex items-center h-7 px-2 gap-0.5 border-b border-[var(--st-border)] flex-shrink-0 overflow-x-auto">
        {tabsWithSep.map((tab) => {
          const isActive = bottomTabs.includes(tab.id);
          const isPrimary = tab.id === bottomPrimaryTab;

          return (
            <span key={tab.id} className="flex items-center">
              {tab.showSep && <Separator orientation="vertical" className="mx-1 h-3.5" />}
              <Tooltip>
                <TooltipTrigger asChild>
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
                    {isActive && <CountBadge count={tabCounts[tab.id]} color="blue" />}
                  </button>
                </TooltipTrigger>
                <TooltipContent>{tab.desc}</TooltipContent>
              </Tooltip>
            </span>
          );
        })}
      </div>
      <div className="flex-1 flex overflow-hidden">
        {bottomTabs.map((tabId, i) => (
          <div
            key={`${tabId}-${bottomPrimaryTab}`}
            className={cn(
              'flex-1 min-w-0 overflow-hidden panel-enter',
              i < bottomTabs.length - 1 && 'border-r border-[var(--st-border)]',
            )}
          >
            {PANEL_MAP[tabId]()}
          </div>
        ))}
      </div>
    </div>
  );
}
