import { StatusDot } from '../common/StatusDot';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';

export function TopBar() {
  const { caseId, caseName, capturing, analysisResult } = useStore();

  const verdictSeverity = analysisResult?.verdict?.severity ?? null;
  const verdictLabel = analysisResult?.verdict?.label ?? 'CLEAN';

  return (
    <div className="glass-heavy h-10 flex items-center border-b border-[var(--st-border)] px-3 gap-4 flex-shrink-0 z-10">
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="w-5 h-5 rounded bg-[var(--st-accent)] flex items-center justify-center">
          <span className="text-white text-[10px] font-black">S</span>
        </div>
        <span className="text-[var(--st-text-label)] text-[11px] font-bold tracking-widest uppercase">
          ShieldTier
        </span>
      </div>

      <div className="w-px h-5 bg-[var(--st-border)]" />

      <div className="flex items-center gap-2 min-w-0">
        {caseId && (
          <span className="text-[var(--st-accent)] text-[11px] font-mono font-bold flex-shrink-0">
            {caseId}
          </span>
        )}
        {caseName && (
          <span className="text-[var(--st-text-label)] text-[11px] truncate">
            {caseName}
          </span>
        )}
      </div>

      <div className="flex-1" />

      {capturing && (
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <StatusDot status="recording" />
          <span className="text-[var(--st-severity-critical)] text-[10px] font-bold tracking-wider">
            REC
          </span>
        </div>
      )}

      <Badge severity={verdictSeverity ?? 'clean'} className="flex-shrink-0">
        {verdictLabel}
      </Badge>
    </div>
  );
}
