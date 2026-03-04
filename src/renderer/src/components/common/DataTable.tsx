import { cn } from '../../lib/utils';

export interface Column<T> {
  key: string;
  label: string;
  width?: string;
  render?: (row: T, index: number) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyFn: (row: T, index: number) => string;
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export function DataTable<T>({ columns, data, keyFn, onRowClick, emptyMessage }: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
        {emptyMessage ?? 'No data'}
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full border-collapse text-[11px] font-mono">
        <thead className="sticky top-0 z-10">
          <tr className="bg-[var(--st-bg-panel)]">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] px-2 py-1.5 border-b border-[var(--st-border)]"
                style={col.width ? { width: col.width } : undefined}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr
              key={keyFn(row, i)}
              onClick={() => onRowClick?.(row)}
              className={cn(
                'h-7 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors',
                onRowClick && 'cursor-pointer',
              )}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-2 py-0 text-[var(--st-text-primary)] truncate max-w-0">
                  {col.render ? col.render(row, i) : String((row as Record<string, unknown>)[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
