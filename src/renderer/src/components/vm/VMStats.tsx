import { cn } from '../../lib/utils';
import { useStore } from '../../store';

interface StatBarProps {
  label: string;
  value: number;
  max: number;
  unit: string;
  getColor: (pct: number) => string;
}

function StatBar({ label, value, max, unit, getColor }: StatBarProps) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-mono">
      <span className="text-[var(--st-text-muted)] w-6 text-right uppercase">{label}</span>
      <div className="w-16 h-1.5 bg-[var(--st-bg-primary)] rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', getColor(pct))} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[var(--st-text-label)] w-12">
        {value}{unit}
      </span>
    </div>
  );
}

function cpuColor(pct: number): string {
  if (pct >= 80) return 'bg-[var(--st-severity-critical)]';
  if (pct >= 50) return 'bg-[var(--st-severity-medium)]';
  return 'bg-[var(--st-severity-clean)]';
}

export function VMStats() {
  const { vmCpuPct, vmRamMb, vmNetKbps } = useStore();
  return (
    <div className="flex items-center gap-3 px-2 py-1 border-t border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      <StatBar label="CPU" value={vmCpuPct} max={100} unit="%" getColor={cpuColor} />
      <StatBar label="RAM" value={vmRamMb} max={512} unit="M" getColor={() => 'bg-[var(--st-severity-medium)]'} />
      <StatBar label="NET" value={vmNetKbps} max={100} unit="KB" getColor={() => 'bg-[var(--st-severity-clean)]'} />
    </div>
  );
}
