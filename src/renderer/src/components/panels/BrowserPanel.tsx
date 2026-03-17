/**
 * BrowserPanel — URL bar, navigation controls, sandboxed BrowserView viewport.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { InvestigationSession, NavigationState, LoadError, SearchEngine } from '../../types';
import { Input } from '../ui/input';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';

const SEARCH_ENGINES: Record<SearchEngine, { label: string; shortLabel: string; url: string }> = {
  google: { label: 'Google', shortLabel: 'G', url: 'https://www.google.com/search?q=' },
  brave: { label: 'Brave', shortLabel: 'B', url: 'https://search.brave.com/search?q=' },
  bing: { label: 'Bing', shortLabel: 'Bi', url: 'https://www.bing.com/search?q=' },
};

function isSearchQuery(input: string): boolean {
  if (input.includes(' ')) return true;
  if (/^[a-zA-Z]+:\/\//.test(input)) return false;
  if (input.includes('.')) return false;
  return true;
}

export function BrowserPanel({ session, navState, loadError, viewReady, captureEnabled, onToggleCapture, onScreenshot, onDOMSnapshot }: {
  session: InvestigationSession;
  navState: NavigationState | null;
  loadError: LoadError | null;
  viewReady: boolean;
  captureEnabled: boolean;
  onToggleCapture: () => void;
  onScreenshot: () => void;
  onDOMSnapshot: () => void;
}) {
  const [urlInput, setUrlInput] = useState('');
  // Initialize from navState so BrowserView is restored after panel tab switches
  const [hasNavigated, setHasNavigated] = useState(
    !!(navState?.url && navState.url !== 'about:blank')
  );
  const viewportRef = useRef<HTMLDivElement>(null);
  const [searchEngine, setSearchEngine] = useState<SearchEngine>(() => {
    return (localStorage.getItem('shieldtier-search-engine') as SearchEngine) || 'google';
  });
  const [showEngineDropdown, setShowEngineDropdown] = useState(false);
  const engineDropdownRef = useRef<HTMLDivElement>(null);

  // Zoom state
  const ZOOM_STEPS = [0.25, 0.33, 0.50, 0.67, 0.75, 0.80, 0.90, 1.00, 1.10, 1.25, 1.50, 1.75, 2.00, 2.50, 3.00];
  const [zoomFactor, setZoomFactor] = useState(1.0);

  const zoomIn = useCallback(() => {
    const nextIdx = ZOOM_STEPS.findIndex(s => s > zoomFactor);
    const next = nextIdx >= 0 ? ZOOM_STEPS[nextIdx] : ZOOM_STEPS[ZOOM_STEPS.length - 1];
    setZoomFactor(next);
    window.shieldtier.view.setZoom(session.id, next);
  }, [session.id, zoomFactor]);

  const zoomOut = useCallback(() => {
    let prevIdx = -1;
    for (let i = ZOOM_STEPS.length - 1; i >= 0; i--) {
      if (ZOOM_STEPS[i] < zoomFactor) { prevIdx = i; break; }
    }
    const prev = prevIdx >= 0 ? ZOOM_STEPS[prevIdx] : ZOOM_STEPS[0];
    setZoomFactor(prev);
    window.shieldtier.view.setZoom(session.id, prev);
  }, [session.id, zoomFactor]);

  const zoomReset = useCallback(() => {
    setZoomFactor(1.0);
    window.shieldtier.view.setZoom(session.id, 1.0);
  }, [session.id]);

  // Update URL bar when navigation happens (user clicked a link)
  useEffect(() => {
    if (navState?.url && navState.url !== 'about:blank') {
      setUrlInput(navState.url);
    }
  }, [navState?.url]);

  // Report viewport bounds to main process so BrowserView is positioned correctly
  const updateBounds = useCallback(() => {
    if (!viewportRef.current) return;
    const rect = viewportRef.current.getBoundingClientRect();
    window.shieldtier.view.setBounds(session.id, {
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
    });
  }, [session.id]);

  // Update bounds on mount, resize, and when view becomes ready.
  // Retry several times after navigation starts because the content browser
  // is created asynchronously — the first setBounds call may arrive before
  // the native view exists, so we resend until it sticks.
  useEffect(() => {
    if (!viewReady || !hasNavigated) return;
    updateBounds();
    // Retry bounds a few times to cover async content browser creation
    const retries = [100, 300, 600, 1000, 2000];
    const timers = retries.map(ms => setTimeout(updateBounds, ms));

    const observer = new ResizeObserver(updateBounds);
    if (viewportRef.current) observer.observe(viewportRef.current);
    window.addEventListener('resize', updateBounds);
    return () => {
      timers.forEach(clearTimeout);
      observer.disconnect();
      window.removeEventListener('resize', updateBounds);
    };
  }, [viewReady, hasNavigated, updateBounds]);

  // Hide BrowserView when engine dropdown is open so native overlay doesn't cover it
  useEffect(() => {
    if (showEngineDropdown) {
      window.shieldtier.view.hide(session.id);
    } else if (viewReady && hasNavigated) {
      updateBounds();
    }
  }, [showEngineDropdown, session.id, viewReady, hasNavigated, updateBounds]);

  // Close engine dropdown on outside click
  useEffect(() => {
    if (!showEngineDropdown) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (engineDropdownRef.current && !engineDropdownRef.current.contains(e.target as Node)) {
        setShowEngineDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showEngineDropdown]);

  // Keyboard shortcuts for zoom (Cmd/Ctrl + =/- /0)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      if (e.key === '=' || e.key === '+') { e.preventDefault(); zoomIn(); }
      else if (e.key === '-') { e.preventDefault(); zoomOut(); }
      else if (e.key === '0') { e.preventDefault(); zoomReset(); }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [zoomIn, zoomOut, zoomReset]);

  const handleSelectEngine = (engine: SearchEngine) => {
    setSearchEngine(engine);
    localStorage.setItem('shieldtier-search-engine', engine);
    setShowEngineDropdown(false);
  };

  const handleNavigate = async () => {
    const trimmed = urlInput.trim();
    if (!trimmed) return;
    setHasNavigated(true);
    const url = isSearchQuery(trimmed)
      ? SEARCH_ENGINES[searchEngine].url + encodeURIComponent(trimmed)
      : trimmed;
    const result = await window.shieldtier.view.navigate(session.id, url);
    if (!result.success && result.error) {
      console.error('Navigation error:', result.error);
    }
    // Schedule bounds update after navigation starts
    requestAnimationFrame(updateBounds);
  };

  const handleBack = () => window.shieldtier.view.goBack(session.id);
  const handleForward = () => window.shieldtier.view.goForward(session.id);
  const handleReload = () => {
    if (navState?.isLoading) {
      window.shieldtier.view.stop(session.id);
    } else {
      window.shieldtier.view.reload(session.id);
    }
  };

  return (
    <TooltipProvider delayDuration={400}>
      <div className="flex flex-col h-full">
        {/* URL bar — Safari-inspired toolbar */}
        <div className="flex items-center gap-1.5 px-2 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
          {/* Nav buttons */}
          <div className="flex items-center gap-px">
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" onClick={handleBack} disabled={!navState?.canGoBack} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M9 3L5 7L9 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </TooltipTrigger>
              <TooltipContent>Back</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" onClick={handleForward} disabled={!navState?.canGoForward} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer">
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M5 3L9 7L5 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </TooltipTrigger>
              <TooltipContent>Forward</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" onClick={handleReload} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer">
                  {navState?.isLoading ? (
                    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                      <path d="M3 3L11 11M11 3L3 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                    </svg>
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                      <path d="M2 7C2 4.24 4.24 2 7 2C9.76 2 12 4.24 12 7C12 9.76 9.76 12 7 12C5.62 12 4.39 11.38 3.55 10.41" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                      <path d="M2 4V7H5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  )}
                </button>
              </TooltipTrigger>
              <TooltipContent>{navState?.isLoading ? 'Stop' : 'Reload'}</TooltipContent>
            </Tooltip>
          </div>

          {/* URL input — unified address bar */}
          <div className="flex-1">
            <div className={cn(
              'flex items-center w-full bg-[color:var(--st-bg-base)] border rounded-md px-2.5 py-1 transition-colors',
              navState?.isLoading ? 'border-[color:var(--st-accent)]' : 'border-[color:var(--st-border)] focus-within:border-[color:var(--st-accent)]'
            )}>
              <span className="text-[9px] text-[color:var(--st-warning)] mr-2 font-mono shrink-0 uppercase font-bold tracking-wider">Sandboxed</span>
              <div className="relative shrink-0 mr-2" ref={engineDropdownRef}>
                <button
                  onClick={() => setShowEngineDropdown(!showEngineDropdown)}
                  className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] border border-[color:var(--st-accent)]/20 rounded hover:brightness-110 transition-colors cursor-pointer"
                  title={`Search with ${SEARCH_ENGINES[searchEngine].label}`}
                  aria-expanded={showEngineDropdown}
                >
                  {SEARCH_ENGINES[searchEngine].label}
                  <svg width="8" height="8" viewBox="0 0 8 8" className="ml-0.5"><path d="M2 3L4 5L6 3" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" fill="none" /></svg>
                </button>
                {showEngineDropdown && (
                  <div className="absolute top-full left-0 mt-1 bg-[color:var(--st-bg-elevated)] border border-[color:var(--st-border)] rounded-lg shadow-2xl z-50 min-w-[120px] py-1">
                    {(Object.keys(SEARCH_ENGINES) as SearchEngine[]).map((key) => (
                      <button
                        key={key}
                        onClick={() => handleSelectEngine(key)}
                        className={cn(
                          'w-full text-left px-3 py-1.5 text-[11px] transition-colors cursor-pointer',
                          key === searchEngine
                            ? 'text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)]'
                            : 'text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] hover:text-[color:var(--st-text-primary)]'
                        )}
                      >
                        {SEARCH_ENGINES[key].label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {navState?.isLoading && (
                <span className="mr-2 w-3 h-3 border-2 border-[color:var(--st-accent)]/30 border-t-[color:var(--st-accent)] rounded-full animate-spin shrink-0" />
              )}
              <Input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Search or enter URL..."
                className="flex-1 bg-transparent border-0 h-auto py-0 px-0 text-[12px] font-mono text-[color:var(--st-text-primary)] placeholder-[color:var(--st-text-muted)] focus:outline-none shadow-none rounded"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleNavigate();
                }}
              />
              {urlInput && (
                <button
                  type="button"
                  onClick={() => { setUrlInput(''); }}
                  className="w-5 h-5 ml-1 flex items-center justify-center rounded text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] cursor-pointer"
                >
                  <svg width="10" height="10" viewBox="0 0 12 12"><path d="M3 3L9 9M9 3L3 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
                </button>
              )}
            </div>
          </div>

          {/* Go button */}
          <button
            type="button"
            onClick={handleNavigate}
            disabled={!urlInput.trim()}
            className="h-7 px-3 rounded-md text-[11px] font-medium bg-[color:var(--st-accent)] text-white hover:brightness-110 disabled:opacity-30 transition-colors cursor-pointer"
          >
            Go
          </button>

          {/* Separator */}
          <span className="w-px h-5 bg-[color:var(--st-border)] mx-0.5" />

          {/* Record toggle */}
          <button
            type="button"
            onClick={onToggleCapture}
            className={cn(
              'h-7 px-2.5 rounded-md text-[11px] font-medium flex items-center gap-1.5 border transition-colors cursor-pointer',
              captureEnabled
                ? 'bg-[color:var(--st-danger-dim)] text-[color:var(--st-danger)] border-[color:var(--st-danger)]/20 hover:brightness-110'
                : 'bg-transparent text-[color:var(--st-text-muted)] border-[color:var(--st-border)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)]'
            )}
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', captureEnabled ? 'bg-[color:var(--st-danger)] animate-pulse' : 'bg-[color:var(--st-text-muted)]')} />
            {captureEnabled ? 'Stop' : 'Record'}
          </button>

          {/* Screenshot */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" onClick={onScreenshot} disabled={!captureEnabled} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <rect x="1" y="3" width="12" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
                  <circle cx="7" cy="7.5" r="2" stroke="currentColor" strokeWidth="1.2" />
                  <path d="M5 3L5.5 1.5H8.5L9 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                </svg>
              </button>
            </TooltipTrigger>
            <TooltipContent>Take screenshot</TooltipContent>
          </Tooltip>

          {/* DOM Snapshot */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" onClick={onDOMSnapshot} disabled={!captureEnabled} className="w-7 h-7 rounded-md flex items-center justify-center text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M4 2L2 4.5L4 7" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M10 2L12 4.5L10 7" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M8 1L6 8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                  <rect x="1" y="9.5" width="12" height="3" rx="0.5" stroke="currentColor" strokeWidth="1.2" />
                  <line x1="4" y1="11" x2="10" y2="11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                </svg>
              </button>
            </TooltipTrigger>
            <TooltipContent>Capture DOM snapshot</TooltipContent>
          </Tooltip>

          {/* Separator */}
          <span className="w-px h-4 bg-[color:var(--st-border)] mx-0.5" />

          {/* Zoom controls */}
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" onClick={zoomOut} disabled={zoomFactor <= 0.25} className="w-6 h-7 rounded flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] disabled:opacity-30 cursor-pointer" aria-label="Zoom out">
                <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
                  <line x1="2" y1="6" x2="10" y2="6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
                </svg>
              </button>
            </TooltipTrigger>
            <TooltipContent>Zoom out (Cmd-)</TooltipContent>
          </Tooltip>
          <button
            type="button"
            onDoubleClick={zoomReset}
            className="px-0.5 text-[10px] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] font-mono min-w-[32px] text-center select-none cursor-pointer"
            aria-label="Reset zoom"
          >
            {Math.round(zoomFactor * 100)}%
          </button>
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" onClick={zoomIn} disabled={zoomFactor >= 3.0} className="w-6 h-7 rounded flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] disabled:opacity-30 cursor-pointer" aria-label="Zoom in">
                <svg width="10" height="10" viewBox="0 0 12 12" fill="none">
                  <line x1="2" y1="6" x2="10" y2="6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
                  <line x1="6" y1="2" x2="6" y2="10" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
                </svg>
              </button>
            </TooltipTrigger>
            <TooltipContent>Zoom in (Cmd+)</TooltipContent>
          </Tooltip>
        </div>

        {/* Loading bar */}
        {navState?.isLoading && (
          <div className="h-0.5 bg-[color:var(--st-bg-base)] overflow-hidden">
            <div className="h-full bg-[color:var(--st-accent)] shimmer w-full" />
          </div>
        )}

        {/* Load error banner */}
        {loadError && (
          <div className="px-3 py-1.5 bg-[color:var(--st-danger-dim)] border-b border-[color:var(--st-danger)]/20 text-[11px] text-[color:var(--st-danger)] flex items-center justify-between">
            <span>Failed to load: {loadError.errorDescription} (<span className="font-mono">{loadError.url}</span>)</span>
            <button type="button" onClick={() => handleReload()} className="text-[color:var(--st-danger)] hover:brightness-125 underline text-[11px] cursor-pointer">Retry</button>
          </div>
        )}

        {/* Browser viewport — BrowserView overlays this div */}
        <div ref={viewportRef} className="flex-1 relative bg-[color:var(--st-bg-base)]">
          {!hasNavigated && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center max-w-sm">
                <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-[color:var(--st-accent-dim)] flex items-center justify-center">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--st-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                </div>
                <p className="text-sm font-medium text-[color:var(--st-text-primary)] mb-1">Sandboxed Browser</p>
                <p className="text-xs text-[color:var(--st-text-secondary)] mb-1">Enter a URL above to begin your investigation</p>
                <p className="text-[11px] text-[color:var(--st-text-muted)]">All traffic is isolated. Zero data persists after session close.</p>
                <details className="mt-4 text-[11px] text-[color:var(--st-text-muted)]">
                  <summary className="cursor-pointer hover:text-[color:var(--st-text-secondary)]">Session details</summary>
                  <div className="mt-2 space-y-0.5 font-mono text-left inline-block">
                    <p>Session: {session.id.slice(0, 8)} | Partition: {session.partition}</p>
                    <p>Sandbox: nodeIntegration=false, contextIsolation=true</p>
                    {session.proxyConfig && (
                      <p>Proxy: {session.proxyConfig.type}://{session.proxyConfig.host}:{session.proxyConfig.port}</p>
                    )}
                  </div>
                </details>
              </div>
            </div>
          )}
        </div>

        {/* Status bar — macOS style */}
        <div className="flex items-center justify-between px-3 py-0.5 border-t border-[color:var(--st-border)] text-[10px] text-[color:var(--st-text-muted)]" style={{ background: 'var(--st-bg-panel)' }}>
          <span className="truncate">{navState?.title || 'Ready'}</span>
          <div className="flex items-center gap-2.5">
            {captureEnabled && (
              <span className="text-[color:var(--st-danger)] font-bold text-[9px]">REC</span>
            )}
            {navState?.url && navState.url !== 'about:blank' && (
              <span className="truncate max-w-xs font-mono" title={navState.url}>{navState.url}</span>
            )}
            <span className={navState?.isLoading ? 'text-[color:var(--st-accent)]' : 'text-[color:var(--st-success)]'}>
              {navState?.isLoading ? 'Loading...' : 'Idle'}
            </span>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}
