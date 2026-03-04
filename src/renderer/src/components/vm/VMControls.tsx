import { useState, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/Tooltip';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';

const OS_OPTIONS = ['Alpine 3.19', 'ReactOS 0.4', 'Windows 10 x64'];

export function VMControls() {
  const { vmStatus } = useStore();
  const [selectedOs, setSelectedOs] = useState(OS_OPTIONS[0]);

  const statusLabel = vmStatus === 'running' ? 'RUNNING' : vmStatus === 'booting' ? 'BOOTING' : vmStatus === 'complete' ? 'COMPLETE' : vmStatus === 'error' ? 'ERROR' : 'IDLE';
  const statusSeverity = vmStatus === 'running' ? 'clean' as const : vmStatus === 'booting' ? 'medium' as const : vmStatus === 'complete' ? 'info' as const : vmStatus === 'error' ? 'critical' as const : 'low' as const;
  const dotStatus = vmStatus === 'running' ? 'active' as const : vmStatus === 'error' ? 'error' as const : 'idle' as const;

  const startVm = useCallback(async () => {
    if (vmStatus !== 'idle' && vmStatus !== 'complete' && vmStatus !== 'error') return;
    try {
      await ipcCall('start_vm', { os: selectedOs });
    } catch (e) {
      console.error('Failed to start VM:', e);
    }
  }, [vmStatus, selectedOs]);

  const stopVm = useCallback(async () => {
    if (vmStatus !== 'running' && vmStatus !== 'booting') return;
    try {
      await ipcCall('stop_vm', {});
    } catch (e) {
      console.error('Failed to stop VM:', e);
    }
  }, [vmStatus]);

  return (
    <div className="flex items-center h-8 px-2 gap-2 border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      <div className="relative">
        <select
          value={selectedOs}
          onChange={(e) => setSelectedOs(e.target.value)}
          disabled={vmStatus === 'running' || vmStatus === 'booting'}
          className="appearance-none bg-[var(--st-bg-primary)] border border-[var(--st-border)] rounded text-[var(--st-text-label)] text-[10px] font-mono px-1.5 py-0.5 pr-5 outline-none cursor-pointer disabled:opacity-50"
        >
          {OS_OPTIONS.map((os) => (
            <option key={os} value={os}>{os}</option>
          ))}
        </select>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--st-text-muted)" strokeWidth="2" className="absolute right-1.5 top-1/2 -translate-y-1/2 pointer-events-none">
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </div>

      <div className="flex items-center gap-1.5">
        <StatusDot status={dotStatus} />
        <Badge severity={statusSeverity}>{statusLabel}</Badge>
      </div>

      <div className="flex items-center gap-1">
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={startVm}
              disabled={vmStatus !== 'idle' && vmStatus !== 'complete' && vmStatus !== 'error'}
              className={cn(
                'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
                (vmStatus === 'idle' || vmStatus === 'complete' || vmStatus === 'error')
                  ? 'bg-[var(--st-severity-clean)]/15 text-[var(--st-severity-clean)] hover:bg-[var(--st-severity-clean)]/25'
                  : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
              )}
            >
              {vmStatus === 'error' ? 'RESET' : 'START'}
            </button>
          </TooltipTrigger>
          <TooltipContent>{vmStatus === 'error' ? 'Reset and restart VM' : 'Start VM sandbox'}</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={stopVm}
              disabled={vmStatus !== 'running' && vmStatus !== 'booting'}
              className={cn(
                'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
                (vmStatus === 'running' || vmStatus === 'booting')
                  ? 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)] hover:bg-[var(--st-severity-critical)]/25'
                  : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
              )}
            >
              STOP
            </button>
          </TooltipTrigger>
          <TooltipContent>Stop VM sandbox</TooltipContent>
        </Tooltip>
      </div>

      <div className="flex-1" />

      {vmStatus === 'error' && (
        <Badge severity="critical">ERROR</Badge>
      )}

      {(vmStatus === 'running' || vmStatus === 'booting') && (
        <Badge severity="critical" className="animate-pulse">
          {vmStatus === 'booting' ? 'BOOTING...' : 'LIVE - ANALYZING'}
        </Badge>
      )}
    </div>
  );
}
