import { useCallback, useRef, useState } from 'react';
import { cn } from '../../lib/utils';

interface SplitterHProps {
  onDrag: (deltaY: number) => void;
  onDragEnd?: () => void;
}

export function SplitterH({ onDrag, onDragEnd }: SplitterHProps) {
  const dragging = useRef(false);
  const lastY = useRef(0);
  const [active, setActive] = useState(false);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastY.current = e.clientY;
    setActive(true);
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientY - lastY.current);
    lastY.current = e.clientY;
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
        'h-[5px] flex-shrink-0 cursor-ns-resize flex items-center justify-center border-t border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/10 transition-colors',
        active && 'bg-[var(--st-accent)]/20',
      )}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="flex gap-1">
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-30')} />
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-30')} />
        <div className={cn('w-[3px] h-[3px] rounded-full transition-colors', active ? 'bg-[var(--st-accent)]/60' : 'bg-[var(--st-text-muted)] opacity-30')} />
      </div>
    </div>
  );
}
