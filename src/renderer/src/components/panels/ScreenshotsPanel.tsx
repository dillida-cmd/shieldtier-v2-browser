import { useState } from 'react';
import { useStore } from '../../store';
import { EmptyState, SkeletonRow } from '../ui/EmptyState';

export function ScreenshotsPanel() {
  const { screenshots, vmStatus } = useStore();
  const [lightbox, setLightbox] = useState<string | null>(null);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Screenshots</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{screenshots.length}</span>
      </div>
      <div className="flex-1 overflow-auto p-2">
        {vmStatus === 'running' && screenshots.length === 0 ? (
          <SkeletonRow count={4} />
        ) : screenshots.length === 0 ? (
          <EmptyState message="No screenshots captured" submessage="Screenshots appear during VM sandbox execution" />
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {screenshots.map((url, i) => (
              <div
                key={i}
                className="rounded border border-[var(--st-border)] overflow-hidden cursor-pointer hover:border-[var(--st-accent)] transition-colors"
                onClick={() => setLightbox(url)}
              >
                <img src={url} alt={`Screenshot ${i + 1}`} className="w-full h-auto" />
              </div>
            ))}
          </div>
        )}
      </div>

      {lightbox && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overlay-enter"
          style={{ background: 'rgba(0, 0, 0, 0.80)' }}
          onClick={() => setLightbox(null)}
        >
          <div className="max-w-[80vw] max-h-[80vh] dialog-enter" onClick={(e) => e.stopPropagation()}>
            <img src={lightbox} alt="Screenshot" className="max-w-full max-h-[80vh] rounded border border-[var(--st-border)]" />
          </div>
        </div>
      )}
    </div>
  );
}
