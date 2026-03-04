import { StatusDot } from '../common/StatusDot';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/Tooltip';

export function TopBar() {
  const { caseId, caseName, capturing, analysisStatus, analysisResult, currentDownload, setModalState } = useStore();

  const verdictSeverity = analysisResult?.verdict?.severity ?? null;
  const verdictLabel = analysisResult?.verdict?.label ?? null;
  const isMalicious = verdictSeverity === 'critical' || verdictSeverity === 'high';

  return (
    <div className={`glass-heavy h-10 flex items-center border-b border-[var(--st-border)] px-3 gap-4 flex-shrink-0 z-10 ${isMalicious ? 'threat-glow' : ''}`}>
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="w-5 h-5 rounded bg-[var(--st-accent)] flex items-center justify-center">
          <span className="text-[var(--st-bg-primary)] text-[10px] font-black glow">S</span>
        </div>
        <span className="text-[var(--st-text-label)] text-[11px] font-bold tracking-widest uppercase">
          ShieldTier
        </span>
      </div>

      <div className="w-px h-5 bg-[var(--st-border)]" />

      <button
        onClick={() => setModalState('caseName')}
        className="flex items-center gap-2 min-w-0 hover:opacity-80 transition-opacity cursor-pointer bg-transparent border-none p-0"
      >
        {caseId ? (
          <span className="text-[var(--st-accent)] text-[11px] font-mono font-bold flex-shrink-0">
            {caseId}
          </span>
        ) : (
          <span className="text-[var(--st-text-muted)] text-[11px] font-mono">NO CASE</span>
        )}
        {caseName && (
          <span className="text-[var(--st-text-label)] text-[11px] truncate">
            {caseName}
          </span>
        )}
      </button>

      <div className="flex-1" />

      {currentDownload && (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-1.5 flex-shrink-0">
              <StatusDot status="active" />
              <span className="text-[var(--st-text-primary)] text-[10px] font-mono truncate max-w-32">
                {currentDownload.filename}
              </span>
              <span className="text-[var(--st-text-muted)] text-[10px]">
                {(currentDownload.size / 1024).toFixed(0)}KB
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent>Download: {currentDownload.filename}</TooltipContent>
        </Tooltip>
      )}

      {capturing && (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-1.5 flex-shrink-0">
              <StatusDot status="recording" />
              <span className="text-[var(--st-severity-critical)] text-[10px] font-bold tracking-wider">
                REC
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent>Network capture active</TooltipContent>
        </Tooltip>
      )}

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => setModalState('settings')}
            className="flex-shrink-0 w-6 h-6 flex items-center justify-center rounded hover:bg-[var(--st-bg-hover)] transition-colors cursor-pointer bg-transparent border-none"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--st-text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
            </svg>
          </button>
        </TooltipTrigger>
        <TooltipContent>Settings (Cmd+,)</TooltipContent>
      </Tooltip>

      {analysisStatus === 'pending' ? (
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <div className="w-3 h-3 border-2 border-[var(--st-accent)] border-t-transparent rounded-full animate-spin" />
          <span className="text-[var(--st-accent)] text-[10px] font-bold tracking-wider">SCANNING...</span>
        </div>
      ) : verdictSeverity && verdictLabel ? (
        <Badge severity={verdictSeverity} className="flex-shrink-0">
          {verdictLabel}
        </Badge>
      ) : null}
    </div>
  );
}
