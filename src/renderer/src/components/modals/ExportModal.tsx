import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';
import { cn } from '../../lib/utils';
import type { HarLog, SeverityLevel } from '../../ipc/types';

type ExportFormat = 'html' | 'json' | 'zip';

interface SectionToggle {
  key: string;
  label: string;
  count: number;
}

function parseHarEntryCount(harString: string): number {
  if (!harString) return 0;
  try {
    const har: HarLog = JSON.parse(harString);
    return har.log.entries.length;
  } catch {
    return 0;
  }
}

function extractIOCCount(findings: Array<{ metadata: Record<string, unknown>; severity: SeverityLevel }>): number {
  const seen = new Set<string>();
  for (const f of findings) {
    const meta = f.metadata;
    if (typeof meta.domain === 'string') seen.add(meta.domain);
    if (typeof meta.destination === 'string') seen.add(meta.destination);
    if (typeof meta.path === 'string' && (meta.path as string).match(/^https?:\/\//)) seen.add(meta.path as string);
  }
  return seen.size;
}

export function ExportModal() {
  const {
    modalState,
    setModalState,
    captureData,
    analysisResult,
    screenshots,
    capturedFiles,
    vmEvents,
    vmFindings,
  } = useStore();

  const [title, setTitle] = useState('ShieldTier Investigation Report');
  const [analyst, setAnalyst] = useState('');
  const [notes, setNotes] = useState('');
  const [format, setFormat] = useState<ExportFormat>('html');
  const [sections, setSections] = useState<Record<string, boolean>>({
    network: true,
    ioc: true,
    files: true,
    screenshots: true,
    timeline: true,
  });
  const [exporting, setExporting] = useState(false);
  const [progress, setProgress] = useState(0);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  const networkCount = useMemo(
    () => parseHarEntryCount(captureData?.har ?? ''),
    [captureData?.har],
  );

  const iocCount = useMemo(() => {
    const allFindings = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return extractIOCCount(allFindings);
  }, [analysisResult, vmFindings]);

  const sectionDefs: SectionToggle[] = useMemo(() => [
    { key: 'network', label: 'Network', count: networkCount },
    { key: 'ioc', label: 'IOC', count: iocCount },
    { key: 'files', label: 'Files', count: capturedFiles.length },
    { key: 'screenshots', label: 'Screenshots', count: screenshots.length },
    { key: 'timeline', label: 'Timeline', count: vmEvents.length },
  ], [networkCount, iocCount, capturedFiles.length, screenshots.length, vmEvents.length]);

  const close = useCallback(() => {
    setModalState('none');
    setExporting(false);
    setProgress(0);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, [setModalState]);

  useEffect(() => {
    if (modalState !== 'export') return;

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') close();
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [modalState, close]);

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const toggleSection = useCallback((key: string) => {
    setSections((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const handleExport = useCallback(async () => {
    setExporting(true);
    setProgress(0);

    intervalRef.current = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) return prev;
        return prev + Math.random() * 15;
      });
    }, 200);

    try {
      const enabledSections = Object.entries(sections)
        .filter(([, v]) => v)
        .map(([k]) => k);

      await ipcCall('export_report', { title, analyst, notes, sections: enabledSections, format });

      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      setProgress(100);

      setTimeout(() => {
        close();
      }, 500);
    } catch {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      setExporting(false);
      setProgress(0);
    }
  }, [sections, title, analyst, notes, format, close]);

  if (modalState !== 'export') return null;

  const formats: ExportFormat[] = ['html', 'json', 'zip'];

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0, 0, 0, 0.6)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => {
        if (e.target === overlayRef.current) close();
      }}
    >
      <div
        className="w-full max-w-lg rounded border p-6 flex flex-col gap-4"
        style={{
          background: 'var(--st-glass-bg)',
          borderColor: 'var(--st-border)',
        }}
      >
        {/* Title */}
        <h2
          className="text-sm font-bold uppercase tracking-wider m-0"
          style={{ color: 'var(--st-text-label)' }}
        >
          EXPORT REPORT
        </h2>

        {/* Report title */}
        <div className="flex flex-col gap-1">
          <label
            className="text-[10px] font-bold uppercase tracking-wider"
            style={{ color: 'var(--st-text-muted)' }}
          >
            REPORT TITLE
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--st-accent)]"
            style={{
              background: 'var(--st-glass-input-bg)',
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-primary)',
            }}
          />
        </div>

        {/* Analyst name */}
        <div className="flex flex-col gap-1">
          <label
            className="text-[10px] font-bold uppercase tracking-wider"
            style={{ color: 'var(--st-text-muted)' }}
          >
            ANALYST NAME
          </label>
          <input
            type="text"
            value={analyst}
            onChange={(e) => setAnalyst(e.target.value)}
            placeholder="Enter your name..."
            className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors placeholder:text-[var(--st-text-muted)] focus:border-[var(--st-accent)]"
            style={{
              background: 'var(--st-glass-input-bg)',
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-primary)',
            }}
          />
        </div>

        {/* Notes */}
        <div className="flex flex-col gap-1">
          <label
            className="text-[10px] font-bold uppercase tracking-wider"
            style={{ color: 'var(--st-text-muted)' }}
          >
            NOTES
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            placeholder="Additional notes..."
            className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none resize-none transition-colors placeholder:text-[var(--st-text-muted)] focus:border-[var(--st-accent)]"
            style={{
              background: 'var(--st-glass-input-bg)',
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-primary)',
            }}
          />
        </div>

        {/* Section toggles */}
        <div className="flex flex-col gap-1.5">
          {sectionDefs.map((s) => (
            <label
              key={s.key}
              className="flex items-center gap-2 cursor-pointer group"
            >
              <input
                type="checkbox"
                checked={sections[s.key]}
                onChange={() => toggleSection(s.key)}
                className={cn(
                  'appearance-none w-4 h-4 rounded-sm border cursor-pointer transition-colors flex-shrink-0',
                  sections[s.key] && 'border-transparent',
                )}
                style={{
                  borderColor: sections[s.key] ? 'var(--st-accent)' : 'var(--st-border)',
                  background: sections[s.key] ? 'var(--st-accent)' : 'transparent',
                }}
              />
              <span
                className="text-xs flex-1"
                style={{ color: 'var(--st-text-primary)' }}
              >
                {s.label}
              </span>
              <span
                className="font-mono text-[10px]"
                style={{ color: 'var(--st-text-muted)' }}
              >
                {s.count}
              </span>
            </label>
          ))}
        </div>

        {/* Format selector */}
        <div className="flex gap-2">
          {formats.map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={cn(
                'flex-1 py-1.5 rounded text-xs font-mono uppercase cursor-pointer transition-colors border',
              )}
              style={{
                background: format === f ? 'var(--st-accent)' : 'var(--st-glass-input-bg)',
                borderColor: format === f ? 'var(--st-accent)' : 'var(--st-border)',
                color: format === f ? 'var(--st-bg-primary)' : 'var(--st-text-label)',
                fontWeight: format === f ? 700 : 400,
              }}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Progress bar */}
        {exporting && (
          <div
            className="w-full h-1 rounded overflow-hidden"
            style={{ background: 'var(--st-bg-elevated)' }}
          >
            <div
              className="h-full rounded transition-all duration-200"
              style={{
                width: `${Math.min(progress, 100)}%`,
                background: 'var(--st-accent)',
              }}
            />
          </div>
        )}

        {/* Buttons */}
        <div className="flex justify-end gap-2">
          <button
            onClick={close}
            className="px-4 py-1.5 rounded text-xs font-mono uppercase cursor-pointer transition-colors border bg-transparent"
            style={{
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-label)',
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="px-4 py-1.5 rounded text-xs font-mono uppercase cursor-pointer transition-colors border-none disabled:opacity-40 disabled:cursor-not-allowed"
            style={{
              background: 'var(--st-accent)',
              color: 'var(--st-bg-primary)',
              fontWeight: 700,
            }}
          >
            Export
          </button>
        </div>
      </div>
    </div>
  );
}
