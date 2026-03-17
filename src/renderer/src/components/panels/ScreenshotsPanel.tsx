/**
 * ScreenshotsPanel — Screenshots and DOM snapshot display with evidence export.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { ScrollArea } from '../ui/scroll-area';
import type { Screenshot, DOMSnapshot } from '../../types';

// Simple HTML prettifier — indents tags for readable preview
function prettifyHTML(html: string, maxLen = 8000): string {
  const truncated = html.length > maxLen ? html.slice(0, maxLen) : html;
  let indent = 0;
  const lines: string[] = [];
  // Split on tag boundaries
  const tokens = truncated.split(/(<\/?[^>]+>)/g).filter(Boolean);
  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('</')) {
      indent = Math.max(0, indent - 1);
      lines.push('  '.repeat(indent) + trimmed);
    } else if (trimmed.startsWith('<') && !trimmed.startsWith('<!') && !trimmed.endsWith('/>') && !isVoidTag(trimmed)) {
      lines.push('  '.repeat(indent) + trimmed);
      indent++;
    } else if (trimmed.startsWith('<')) {
      lines.push('  '.repeat(indent) + trimmed);
    } else {
      // Text content — keep on same indent
      const text = trimmed.length > 200 ? trimmed.slice(0, 200) + '...' : trimmed;
      if (text) lines.push('  '.repeat(indent) + text);
    }
  }
  const result = lines.join('\n');
  if (html.length > maxLen) return result + '\n\n  ... [truncated — ' + (html.length / 1024).toFixed(0) + ' KB total]';
  return result;
}

const VOID_TAGS = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
function isVoidTag(tag: string): boolean {
  const m = tag.match(/^<(\w+)/);
  return m ? VOID_TAGS.has(m[1].toLowerCase()) : false;
}

function saveText(content: string, filename: string) {
  (window.shieldtier?.report as any)?.saveFile?.(content, filename, 'html');
}

function savePNG(dataUrl: string, filename: string) {
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  );
}

export function ScreenshotsPanel({ screenshots, domSnapshots, captureEnabled, onScreenshot, onDOMSnapshot }: {
  screenshots: Screenshot[];
  domSnapshots: DOMSnapshot[];
  captureEnabled: boolean;
  onScreenshot: () => void;
  onDOMSnapshot: () => void;
}) {
  const [subTab, setSubTab] = useState<'screenshots' | 'dom'>('screenshots');
  const [previewScreenshot, setPreviewScreenshot] = useState<Screenshot | null>(null);
  const [expandedDom, setExpandedDom] = useState<string | null>(null);

  const navigatePreview = useCallback((direction: 'prev' | 'next') => {
    if (!previewScreenshot || screenshots.length <= 1) return;
    const currentIdx = screenshots.findIndex(s => s.id === previewScreenshot.id);
    if (currentIdx < 0) return;
    const nextIdx = direction === 'next'
      ? (currentIdx + 1) % screenshots.length
      : (currentIdx - 1 + screenshots.length) % screenshots.length;
    setPreviewScreenshot(screenshots[nextIdx]);
  }, [previewScreenshot, screenshots]);

  useEffect(() => {
    if (!previewScreenshot && !expandedDom) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setPreviewScreenshot(null);
        setExpandedDom(null);
      } else if (previewScreenshot) {
        if (e.key === 'ArrowLeft') navigatePreview('prev');
        else if (e.key === 'ArrowRight') navigatePreview('next');
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [previewScreenshot, expandedDom, navigatePreview]);

  const expandedSnap = expandedDom ? domSnapshots.find(s => s.id === expandedDom) : null;

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
        <div className="flex items-center bg-[color:var(--st-bg-base)] rounded-md border border-[color:var(--st-border)] p-px">
          <button
            type="button"
            onClick={() => setSubTab('screenshots')}
            className={cn(
              'h-[22px] px-2.5 rounded text-[10px] font-medium transition-colors cursor-pointer',
              subTab === 'screenshots' ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
            )}
          >
            Screenshots ({screenshots.length})
          </button>
          <button
            type="button"
            onClick={() => setSubTab('dom')}
            className={cn(
              'h-[22px] px-2.5 rounded text-[10px] font-medium transition-colors cursor-pointer',
              subTab === 'dom' ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
            )}
          >
            DOM Snapshots ({domSnapshots.length})
          </button>
        </div>
        <div className="flex-1" />

        {/* Export All button — stagger downloads 300ms apart so CEF doesn't block */}
        {subTab === 'screenshots' && screenshots.length > 1 && (
          <button
            type="button"
            className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer"
            onClick={() => screenshots.forEach((ss, i) => setTimeout(() => savePNG(ss.dataUrl, `screenshot-${i + 1}-${ss.id}.png`), i * 300))}
          >
            Export All
          </button>
        )}
        {subTab === 'dom' && domSnapshots.length > 1 && (
          <button
            type="button"
            className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer"
            onClick={() => domSnapshots.forEach((snap, i) => setTimeout(() => saveText(snap.html,`dom-snapshot-${i + 1}-${snap.id}.html`), i * 300))}
          >
            Export All
          </button>
        )}

        {subTab === 'screenshots' && (
          <button
            type="button"
            onClick={onScreenshot}
            disabled={!captureEnabled}
            className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer"
          >
            Take Screenshot
          </button>
        )}
        {subTab === 'dom' && (
          <button
            type="button"
            onClick={onDOMSnapshot}
            disabled={!captureEnabled}
            className="h-7 px-2.5 rounded-md text-[11px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] disabled:opacity-30 transition-colors cursor-pointer"
          >
            Capture DOM
          </button>
        )}
      </div>

      {/* Content */}
      <ScrollArea className="flex-1 p-4">
        {/* ---- Screenshots tab ---- */}
        {subTab === 'screenshots' && (
          screenshots.length === 0 ? (
            <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
              {captureEnabled ? 'Click "Take Screenshot" to capture the current page' : 'Start recording to enable screenshots'}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {screenshots.map((ss, idx) => (
                  <div
                    key={ss.id}
                    className="group bg-[color:var(--st-bg-elevated)] rounded-lg border border-[color:var(--st-border)] overflow-hidden hover:border-[color:var(--st-accent)]/30 transition-colors"
                  >
                    <button
                      type="button"
                      onClick={() => setPreviewScreenshot(ss)}
                      className="w-full text-left cursor-pointer"
                    >
                      <img src={ss.dataUrl} alt={ss.title} className="w-full aspect-video object-cover" />
                    </button>
                    <div className="p-2 flex items-center justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] text-[color:var(--st-text-muted)] truncate font-mono" title={ss.url}>{ss.url}</p>
                        <p className="text-[9px] text-[color:var(--st-text-muted)] font-mono">{new Date(ss.timestamp).toLocaleTimeString()}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          className="text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer"
                          onClick={() => savePNG(ss.dataUrl, `screenshot-${idx + 1}-${ss.id}.png`)}
                        >
                          Save PNG
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Fullscreen preview overlay */}
              {previewScreenshot && (
                <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center" onClick={() => setPreviewScreenshot(null)}>
                  {screenshots.length > 1 && (
                    <button
                      onClick={(e) => { e.stopPropagation(); navigatePreview('prev'); }}
                      className="absolute left-4 top-1/2 -translate-y-1/2 z-10 w-10 h-10 rounded-full bg-black/50 hover:bg-black/70 flex items-center justify-center text-white/70 hover:text-white transition-colors cursor-pointer"
                      aria-label="Previous screenshot"
                    >
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M12 4L6 10L12 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                    </button>
                  )}
                  <div className="max-w-[90vw] max-h-[90vh] relative" onClick={(e) => e.stopPropagation()}>
                    <img src={previewScreenshot.dataUrl} alt={previewScreenshot.title} className="max-w-full max-h-[85vh] object-contain rounded-lg" />
                    <div className="mt-2 flex items-center justify-between text-xs gap-4">
                      <span className="text-white/60 font-mono truncate">{previewScreenshot.url}</span>
                      <span className="text-white/40 font-mono shrink-0">{screenshots.findIndex(s => s.id === previewScreenshot.id) + 1} / {screenshots.length}</span>
                      <button
                        type="button"
                        onClick={() => savePNG(previewScreenshot.dataUrl, `screenshot-${previewScreenshot.id}.png`)}
                        className="px-2 py-1 text-[11px] text-[color:var(--st-accent)] hover:underline rounded cursor-pointer shrink-0"
                      >
                        Save PNG
                      </button>
                      <button type="button" onClick={() => setPreviewScreenshot(null)} className="px-2 py-1 text-[11px] text-white/60 hover:text-white rounded transition-colors cursor-pointer shrink-0">
                        Close
                      </button>
                    </div>
                  </div>
                  {screenshots.length > 1 && (
                    <button
                      onClick={(e) => { e.stopPropagation(); navigatePreview('next'); }}
                      className="absolute right-4 top-1/2 -translate-y-1/2 z-10 w-10 h-10 rounded-full bg-black/50 hover:bg-black/70 flex items-center justify-center text-white/70 hover:text-white transition-colors cursor-pointer"
                      aria-label="Next screenshot"
                    >
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M8 4L14 10L8 16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                    </button>
                  )}
                </div>
              )}
            </>
          )
        )}

        {/* ---- DOM Snapshots tab ---- */}
        {subTab === 'dom' && (
          domSnapshots.length === 0 ? (
            <div className="flex items-center justify-center h-full text-xs text-[color:var(--st-text-muted)]">
              {captureEnabled ? 'Click "Capture DOM" to snapshot the current page' : 'Start recording to enable DOM snapshots'}
            </div>
          ) : (
            <div className="space-y-3">
              {domSnapshots.map((snap, idx) => {
                const isExpanded = expandedDom === snap.id;
                return (
                <div key={snap.id} className="bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] overflow-hidden">
                  {/* Header row 1: title + URL */}
                  <div className="px-3 pt-2 pb-1">
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] text-[color:var(--st-text-secondary)] font-medium">
                        DOM Snapshot #{idx + 1}
                        <span className="ml-2 text-[10px] text-[color:var(--st-text-muted)] font-normal font-mono">{new Date(snap.timestamp).toLocaleTimeString()}</span>
                      </p>
                      <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono shrink-0">{(snap.html.length / 1024).toFixed(1)} KB</span>
                    </div>
                    <p className="text-[10px] text-[color:var(--st-text-muted)] truncate font-mono mt-0.5" title={snap.url}>{snap.url}</p>
                  </div>
                  {/* Header row 2: action buttons */}
                  <div className="flex items-center gap-3 px-3 pb-2 border-b border-[color:var(--st-border-subtle)]">
                    <CopyButton text={snap.html} label="Copy HTML" />
                    <button
                      type="button"
                      className="text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer"
                      onClick={() => setExpandedDom(isExpanded ? null : snap.id)}
                    >
                      {isExpanded ? 'Collapse' : 'Expand Full'}
                    </button>
                    <button
                      type="button"
                      className="text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer"
                      onClick={() => saveText(snap.html,`dom-snapshot-${idx + 1}-${snap.id}.html`)}
                    >
                      Save HTML
                    </button>
                  </div>
                  {/* Prettified HTML preview — always scrollable */}
                  <pre className={cn(
                    "text-[10px] leading-[1.6] text-[color:var(--st-text-muted)] bg-[color:var(--st-bg-base)] px-3 py-2 font-mono overflow-x-auto overflow-y-auto",
                    isExpanded ? 'max-h-[60vh]' : 'max-h-48'
                  )}>
                    <code>{prettifyHTML(snap.html, isExpanded ? 200000 : 4000)}</code>
                  </pre>
                </div>
                );
              })}
            </div>
          )
        )}
      </ScrollArea>

      {/* Expanded DOM overlay */}
      {expandedSnap && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-8" onClick={() => setExpandedDom(null)}>
          <div className="w-full max-w-5xl h-full bg-[color:var(--st-bg-panel)] rounded-lg border border-[color:var(--st-border)] flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-4 py-2 border-b border-[color:var(--st-border)]" style={{ background: 'var(--st-bg-toolbar)' }}>
              <div className="min-w-0 flex-1 mr-4">
                <span className="text-[11px] text-[color:var(--st-text-secondary)] font-medium">DOM Snapshot</span>
                <span className="ml-2 text-[10px] text-[color:var(--st-text-muted)] font-mono">{expandedSnap.url}</span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono">{(expandedSnap.html.length / 1024).toFixed(1)} KB</span>
                <CopyButton text={expandedSnap.html} label="Copy HTML" />
                <button
                  type="button"
                  className="text-[10px] text-[color:var(--st-accent)] hover:underline cursor-pointer"
                  onClick={() => saveText(expandedSnap.html,`dom-snapshot-${expandedSnap.id}.html`)}
                >
                  Save HTML
                </button>
                <button type="button" onClick={() => setExpandedDom(null)} className="text-[10px] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] cursor-pointer">Close</button>
              </div>
            </div>
            <ScrollArea className="flex-1">
              <pre className="text-[10px] leading-[1.6] text-[color:var(--st-text-muted)] px-4 py-3 font-mono">
                <code>{prettifyHTML(expandedSnap.html, 500000)}</code>
              </pre>
            </ScrollArea>
          </div>
        </div>
      )}
    </div>
  );
}
