import { useCallback, useRef } from 'react';
import { TopBar } from './TopBar';
import { IconRail } from './IconRail';
import { BrowserZone } from './BrowserZone';
import { VMZone } from './VMZone';
import { DataZone } from './DataZone';
import { SplitterH } from './SplitterH';
import { SplitterV } from './SplitterV';
import { useStore } from '../../store';

export function WorkspaceRoot() {
  const { topSplit, mainSplit, vmCollapsed, setTopSplit, setMainSplit } = useStore();
  const containerRef = useRef<HTMLDivElement>(null);

  const onHSplitterDrag = useCallback((deltaY: number) => {
    const container = containerRef.current;
    if (!container) return;
    const totalHeight = container.clientHeight - 40;
    setMainSplit(useStore.getState().mainSplit + deltaY / totalHeight);
  }, [setMainSplit]);

  const onVSplitterDrag = useCallback((deltaX: number) => {
    const container = containerRef.current;
    if (!container) return;
    const totalWidth = container.clientWidth - 52;
    setTopSplit(useStore.getState().topSplit + deltaX / totalWidth);
  }, [setTopSplit]);

  const topPct = `calc(${mainSplit * 100}% - 2px)`;
  const bottomPct = `calc(${(1 - mainSplit) * 100}% - 2px)`;
  const leftPct = vmCollapsed ? '100%' : `calc(${topSplit * 100}% - 2px)`;
  const rightPct = vmCollapsed ? '0%' : `calc(${(1 - topSplit) * 100}% - 2px)`;

  return (
    <div className="h-screen w-screen flex overflow-hidden">
      <IconRail />
      <div ref={containerRef} className="flex-1 flex flex-col min-w-0">
        <TopBar />
        <div className="flex min-h-0" style={{ height: topPct }}>
          <div className="min-w-0 overflow-hidden" style={{ width: leftPct }}>
            <BrowserZone />
          </div>
          {!vmCollapsed && (
            <>
              <SplitterV onDrag={onVSplitterDrag} />
              <div className="min-w-0 overflow-hidden" style={{ width: rightPct }}>
                <VMZone />
              </div>
            </>
          )}
        </div>
        <SplitterH onDrag={onHSplitterDrag} />
        <div className="min-h-0 overflow-hidden" style={{ height: bottomPct }}>
          <DataZone />
        </div>
      </div>
    </div>
  );
}
