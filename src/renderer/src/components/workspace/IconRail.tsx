import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { useStore, type LayoutPreset } from '../../store';

const PRESETS: Array<{ id: LayoutPreset; label: string }> = [
  { id: 'brw', label: 'BRW' },
  { id: 'eml', label: 'EML' },
  { id: 'mal', label: 'MAL' },
  { id: 'log', label: 'LOG' },
];

export function IconRail() {
  const { preset, setPreset, capturing } = useStore();

  return (
    <div className="glass-heavy w-[52px] border-r border-[var(--st-border)] flex flex-col items-center py-2 flex-shrink-0 gap-1">
      {PRESETS.map((p) => (
        <button
          key={p.id}
          onClick={() => setPreset(p.id)}
          className={cn(
            'w-10 h-9 rounded-lg border-none flex flex-col items-center justify-center cursor-pointer transition-colors text-[9px] font-bold tracking-wider',
            preset === p.id
              ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)] glow-accent'
              : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)]',
          )}
        >
          {p.label}
        </button>
      ))}

      <div className="w-7 h-px bg-[var(--st-border)] my-1" />

      <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2L2 7l10 5 10-5-10-5z" />
          <path d="M2 17l10 5 10-5" />
          <path d="M2 12l10 5 10-5" />
        </svg>
        <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">YARA</span>
        <div className="absolute -top-0.5 -right-0.5">
          <CountBadge count={24} color="purple" />
        </div>
      </button>

      <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 2a10 10 0 0 1 0 20" />
          <path d="M2 12h20" />
        </svg>
        <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">FEED</span>
      </button>

      <div className="flex-1" />

      <div className="flex flex-col items-center gap-0.5 mb-1">
        <StatusDot status={capturing ? 'recording' : 'idle'} />
        <span className={cn(
          'text-[7px] font-bold uppercase tracking-wider',
          capturing ? 'text-[var(--st-severity-critical)]' : 'text-[var(--st-text-muted)]',
        )}>
          REC
        </span>
      </div>
    </div>
  );
}
