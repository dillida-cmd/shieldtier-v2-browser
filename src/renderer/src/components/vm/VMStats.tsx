import { cn } from '../../lib/utils';

interface StatBarProps {
  label: string;
  value: number;
  max: number;
  unit: string;
  color: string;
}

function StatBar({ label, value, max, unit, color }: StatBarProps) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-1.5 text-[9px] font-mono">
      <span className="text-[var(--st-text-muted)] w-6 text-right uppercase">{label}</span>
      <div className="w-16 h-1.5 bg-[var(--st-bg-primary)] rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[var(--st-text-label)] w-12">
        {value}{unit}
      </span>
    </div>
  );
}

export function VMStats() {
  return (
    <div className="flex items-center gap-3 px-2 py-1 border-t border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      <StatBar label="CPU" value={23} max={100} unit="%" color="bg-[var(--st-accent)]" />
      <StatBar label="RAM" value={156} max={512} unit="M" color="bg-[var(--st-severity-medium)]" />
      <StatBar label="NET" value={4} max={100} unit="KB" color="bg-[var(--st-severity-clean)]" />
    </div>
  );
}
