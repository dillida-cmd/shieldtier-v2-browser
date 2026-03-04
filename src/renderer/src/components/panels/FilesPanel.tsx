import { useCallback } from 'react';
import { Badge } from '../common/Badge';
import { DataTable, type Column } from '../common/DataTable';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import { ipcCall } from '../../ipc/bridge';
import type { FileEntry } from '../../ipc/types';

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}

const COLUMNS: Column<FileEntry>[] = [
  {
    key: 'severity',
    label: '',
    width: '20px',
    render: (row) => {
      const sev = row.severity ?? 'info';
      const color: Record<string, string> = {
        critical: 'bg-[var(--st-severity-critical)]',
        high: 'bg-[var(--st-severity-high)]',
        medium: 'bg-[var(--st-severity-medium)]',
        low: 'bg-[var(--st-severity-low)]',
        info: 'bg-[var(--st-text-muted)]',
      };
      return <div className={`w-2 h-2 rounded-full ${color[sev] ?? color.info}`} />;
    },
  },
  {
    key: 'filename',
    label: 'Name',
    render: (row) => <span className="font-mono text-[var(--st-text-primary)]">{row.filename}</span>,
  },
  {
    key: 'size',
    label: 'Size',
    width: '70px',
    render: (row) => <span className="text-[var(--st-text-label)]">{formatSize(row.size)}</span>,
  },
  {
    key: 'mimeType',
    label: 'Type',
    width: '100px',
    render: (row) => <span className="text-[var(--st-text-label)]">{row.mimeType}</span>,
  },
  {
    key: 'sha256',
    label: 'SHA256',
    width: '120px',
    render: (row) => <span className="text-[var(--st-text-muted)] font-mono">{row.sha256.slice(0, 16)}...</span>,
  },
];

export function FilesPanel() {
  const { capturedFiles } = useStore();

  const analyzeFile = useCallback(async (sha256: string) => {
    try {
      await ipcCall('analyze_download', { sha256 });
    } catch (e) {
      console.error('Failed to analyze file:', e);
    }
  }, []);

  const columnsWithAction: Column<FileEntry>[] = [
    ...COLUMNS,
    {
      key: 'action',
      label: '',
      width: '60px',
      render: (row) => (
        <button
          onClick={(e) => { e.stopPropagation(); analyzeFile(row.sha256); }}
          className="text-[10px] font-bold px-1.5 py-0.5 rounded border-none cursor-pointer bg-[var(--st-accent-dim)] text-[var(--st-accent)] hover:bg-[var(--st-accent)]/20 transition-colors"
        >
          Analyze
        </button>
      ),
    },
  ];

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Files</span>
        <span className="text-[10px] font-mono text-[var(--st-text-label)]">{capturedFiles.length}</span>
      </div>
      {capturedFiles.length === 0 ? (
        <EmptyState message="No files captured" submessage="Captured and dropped files will appear here" />
      ) : (
        <DataTable
          columns={columnsWithAction}
          data={capturedFiles}
          keyFn={(row) => row.sha256}
          emptyMessage="No files captured"
        />
      )}
    </div>
  );
}
