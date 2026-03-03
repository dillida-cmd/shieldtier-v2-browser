import { useCallback, useRef } from 'react';

interface SplitterVProps {
  onDrag: (deltaX: number) => void;
  onDragEnd?: () => void;
}

export function SplitterV({ onDrag, onDragEnd }: SplitterVProps) {
  const dragging = useRef(false);
  const lastX = useRef(0);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastX.current = e.clientX;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientX - lastX.current);
    lastX.current = e.clientX;
  }, [onDrag]);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    dragging.current = false;
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className="w-[5px] flex-shrink-0 cursor-ew-resize flex items-center justify-center border-l border-r border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/20 transition-colors"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="h-8 w-[2px] rounded bg-[var(--st-text-muted)] opacity-20" />
    </div>
  );
}
