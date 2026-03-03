import { useCallback, useRef } from 'react';

interface SplitterHProps {
  onDrag: (deltaY: number) => void;
  onDragEnd?: () => void;
}

export function SplitterH({ onDrag, onDragEnd }: SplitterHProps) {
  const dragging = useRef(false);
  const lastY = useRef(0);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastY.current = e.clientY;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientY - lastY.current);
    lastY.current = e.clientY;
  }, [onDrag]);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    dragging.current = false;
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className="h-[5px] flex-shrink-0 cursor-ns-resize flex items-center justify-center border-t border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/20 transition-colors"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="w-10 h-[2px] rounded bg-[var(--st-text-muted)] opacity-30" />
    </div>
  );
}
