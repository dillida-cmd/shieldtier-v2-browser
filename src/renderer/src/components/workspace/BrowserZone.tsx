import { useState, useCallback, useEffect } from 'react';
import { Badge } from '../common/Badge';
import { ipcCall } from '../../ipc/bridge';
import { useStore } from '../../store';

export function BrowserZone() {
  const { navCanGoBack, navCanGoForward, navIsLoading, navCurrentUrl } = useStore();
  const [urlInput, setUrlInput] = useState('');

  const navigate = useCallback(async () => {
    const trimmed = urlInput.trim();
    if (!trimmed) return;

    let target = trimmed;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }

    try {
      await ipcCall('navigate', { url: target });
    } catch (e) {
      console.error('Navigation failed:', e);
    }
  }, [urlInput]);

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') navigate();
  }, [navigate]);

  const goBack = useCallback(() => { ipcCall('nav_back'); }, []);
  const goForward = useCallback(() => { ipcCall('nav_forward'); }, []);
  const reload = useCallback(() => {
    if (navIsLoading) {
      ipcCall('nav_stop');
    } else {
      ipcCall('nav_reload');
    }
  }, [navIsLoading]);

  useEffect(() => { setUrlInput(''); }, [navCurrentUrl]);

  const displayUrl = urlInput || navCurrentUrl;

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-primary)]">
      <div className="flex items-center h-10 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0 bg-[var(--st-bg-panel)]">
        <div className="flex items-center gap-1 flex-shrink-0">
          <NavButton label="Back" onClick={goBack} disabled={!navCanGoBack}>
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </NavButton>
          <NavButton label="Forward" onClick={goForward} disabled={!navCanGoForward}>
            <path d="M5 12h14M12 5l7 7-7 7" />
          </NavButton>
          <NavButton label={navIsLoading ? 'Stop' : 'Refresh'} onClick={reload}>
            {navIsLoading ? (
              <path d="M18 6L6 18M6 6l12 12" />
            ) : (
              <>
                <path d="M23 4v6h-6M1 20v-6h6" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </>
            )}
          </NavButton>
        </div>

        <Badge severity="info" className="flex-shrink-0">SANDBOXED</Badge>

        <div className="flex-1 flex items-center bg-[var(--st-bg-primary)] rounded border border-[var(--st-border)] px-2 h-7">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--st-text-muted)" strokeWidth="2" className="flex-shrink-0 mr-1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <input
            type="text"
            value={displayUrl}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={onKeyDown}
            onFocus={() => { if (!urlInput && navCurrentUrl) setUrlInput(navCurrentUrl); }}
            placeholder="Enter URL to investigate..."
            className="flex-1 bg-transparent border-none outline-none text-[var(--st-text-primary)] font-mono text-[11px] placeholder:text-[var(--st-text-muted)]"
          />
          {navIsLoading && (
            <div className="w-3 h-3 border-2 border-[var(--st-accent)] border-t-transparent rounded-full animate-spin flex-shrink-0" />
          )}
        </div>
      </div>

      {!navCurrentUrl || navCurrentUrl === 'about:blank' || navCurrentUrl.startsWith('shieldtier://') ? (
        <div className="flex-1 flex items-center justify-center bg-[var(--st-bg-primary)]">
          <div className="flex flex-col items-center gap-3 text-[var(--st-text-muted)]">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.3">
              <circle cx="12" cy="12" r="10" />
              <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
            <span className="text-[11px]">Navigate to a URL to begin analysis</span>
          </div>
        </div>
      ) : (
        <div className="flex-1 bg-[var(--st-bg-primary)]" />
      )}
    </div>
  );
}

function NavButton({ label, children, onClick, disabled }: {
  label: string;
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      title={label}
      onClick={onClick}
      disabled={disabled}
      className="w-7 h-7 rounded border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] cursor-pointer transition-colors flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-transparent"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {children}
      </svg>
    </button>
  );
}
