import { VMControls } from '../vm/VMControls';
import { VMTerminal } from '../vm/VMTerminal';
import { VMStats } from '../vm/VMStats';

export function VMZone() {
  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-panel)] border-l border-[var(--st-border)]">
      <div className="flex items-center h-7 px-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">
          VM Sandbox
        </span>
      </div>
      <VMControls />
      <VMTerminal />
      <VMStats />
    </div>
  );
}
