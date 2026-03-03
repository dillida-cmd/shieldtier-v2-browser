import { useCallback, useMemo } from 'react';
import { DataTable, type Column } from '../common/DataTable';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';
import type { HarLog, HarEntry } from '../../ipc/types';

function parseHarEntries(harString: string): HarEntry[] {
  if (!harString) return [];
  try {
    const har: HarLog = JSON.parse(harString);
    return har.log.entries.map((e) => ({
      method: e.request.method,
      url: e.request.url,
      status: e.response.status,
      size: e.response.content.size,
      time: e.time,
      mimeType: e.response.content.mimeType,
    }));
  } catch {
    return [];
  }
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}

function formatTime(ms: number): string {
  if (ms < 1000) return Math.round(ms) + 'ms';
  return (ms / 1000).toFixed(1) + 's';
}

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-[var(--st-severity-clean)]',
  POST: 'text-[var(--st-severity-medium)]',
  PUT: 'text-[var(--st-severity-medium)]',
  DELETE: 'text-[var(--st-severity-critical)]',
};

const COLUMNS: Column<HarEntry>[] = [
  {
    key: 'method',
    label: 'Method',
    width: '60px',
    render: (row) => (
      <span className={METHOD_COLORS[row.method] ?? 'text-[var(--st-text-label)]'}>
        {row.method}
      </span>
    ),
  },
  { key: 'url', label: 'URL' },
  {
    key: 'status',
    label: 'Status',
    width: '60px',
    render: (row) => {
      const severity = row.status >= 400 ? 'high' : row.status >= 300 ? 'medium' : 'clean';
      return <Badge severity={severity}>{row.status}</Badge>;
    },
  },
  {
    key: 'size',
    label: 'Size',
    width: '70px',
    render: (row) => <span className="text-[var(--st-text-label)]">{formatSize(row.size)}</span>,
  },
  {
    key: 'time',
    label: 'Time',
    width: '70px',
    render: (row) => <span className="text-[var(--st-text-label)]">{formatTime(row.time)}</span>,
  },
];

export function NetworkPanel() {
  const { captureData, capturing } = useStore();

  const entries = useMemo(
    () => parseHarEntries(captureData?.har ?? ''),
    [captureData?.har],
  );

  const toggleCapture = useCallback(async () => {
    if (capturing) {
      await ipcCall('stop_capture', { browser_id: 0 });
    } else {
      await ipcCall('start_capture', { browser_id: 0 });
    }
  }, [capturing]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Network</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{entries.length}</span>
        <div className="flex-1" />
        <button
          onClick={toggleCapture}
          className="text-[9px] font-bold border-none bg-transparent cursor-pointer transition-colors px-1.5 py-0.5 rounded"
          style={{ color: capturing ? 'var(--st-severity-critical)' : 'var(--st-severity-clean)' }}
        >
          {capturing ? '■ STOP' : '● REC'}
        </button>
      </div>
      <DataTable
        columns={COLUMNS}
        data={entries}
        keyFn={(_, i) => String(i)}
        emptyMessage="No network requests captured"
      />
    </div>
  );
}
