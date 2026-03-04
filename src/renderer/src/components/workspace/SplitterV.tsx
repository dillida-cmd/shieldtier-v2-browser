import { useCallback, useRef, useState } from 'react';
import { cn } from '../../lib/utils';

interface SplitterVProps {
  onDrag: (deltaX: number) => void;
  onDragEnd?: () => void;
}

export function SplitterV({ onDrag, onDragEnd }: SplitterVProps) {
  const dragging = useRef(false);
  const lastX = useRef(0);
  const [active, setActive] = useState(false);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastX.current = e.clientX;
    setActive(true);
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientX - lastX.current);
    lastX.current = e.clientX;
  }, [onDrag]);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    dragging.current = false;
    setActive(false);
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className={cn(
        'w-[5px] flex-shrink-0 cursor-ew-resize flex items-center justify-center border-l border-r border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/10 transition-colors',
        active && 'bg-[var(--st-accent)]/20',
      )}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="flex flex-col gap-1">
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-20')} />
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-20')} />
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-20')} />
      </div>
    </div>
  );
}
