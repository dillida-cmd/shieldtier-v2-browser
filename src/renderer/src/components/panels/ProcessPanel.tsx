import { useState, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { useStore } from '../../store';
import { EmptyState } from '../ui/EmptyState';
import type { ProcessNode } from '../../ipc/types';

const SUSPICIOUS_PROCS = new Set(['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe']);

function ProcessNodeRow({ node, depth, collapsed, onToggle }: {
  node: ProcessNode;
  depth: number;
  collapsed: Set<number>;
  onToggle: (pid: number) => void;
}) {
  const isCollapsed = collapsed.has(node.pid);
  const hasChildren = node.children.length > 0;
  const isSuspicious = SUSPICIOUS_PROCS.has(node.name.toLowerCase());

  return (
    <>
      <div
        className="flex items-center gap-1 px-2 py-0.5 hover:bg-[var(--st-bg-hover)] transition-colors font-mono text-[11px] cursor-pointer"
        style={{ paddingLeft: `${8 + depth * 16}px` }}
        onClick={() => hasChildren && onToggle(node.pid)}
      >
        {hasChildren ? (
          <span className={cn('text-[var(--st-text-muted)] transition-transform text-[10px]', isCollapsed ? '' : 'rotate-90')}>▶</span>
        ) : (
          <span className="text-[var(--st-border)] ml-1.5">&middot;</span>
        )}
        <span className={cn(isSuspicious ? 'text-[var(--st-severity-medium)]' : 'text-[var(--st-severity-clean)]')}>
          {node.name}
        </span>
        <span className="text-[var(--st-text-muted)] text-[10px]">pid={node.pid}</span>
      </div>
      {hasChildren && !isCollapsed && (
        <div className="collapse-enter">
          {node.children.map((child) => (
            <ProcessNodeRow key={child.pid} node={child} depth={depth + 1} collapsed={collapsed} onToggle={onToggle} />
          ))}
        </div>
      )}
    </>
  );
}

export function ProcessPanel() {
  const { vmProcessTree } = useStore();
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());

  const onToggle = useCallback((pid: number) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid); else next.add(pid);
      return next;
    });
  }, []);

  const expandAll = useCallback(() => setCollapsed(new Set()), []);
  const collapseAll = useCallback(() => {
    const pids = new Set<number>();
    const walk = (nodes: ProcessNode[]) => { for (const n of nodes) { if (n.children.length) pids.add(n.pid); walk(n.children); } };
    walk(vmProcessTree);
    setCollapsed(pids);
  }, [vmProcessTree]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Process Tree</span>
        <div className="flex-1" />
        {vmProcessTree.length > 0 && (
          <div className="flex gap-1">
            <button onClick={expandAll} className="text-[10px] text-[var(--st-text-muted)] hover:text-[var(--st-text-label)] bg-transparent border-none cursor-pointer">
              Expand
            </button>
            <button onClick={collapseAll} className="text-[10px] text-[var(--st-text-muted)] hover:text-[var(--st-text-label)] bg-transparent border-none cursor-pointer">
              Collapse
            </button>
          </div>
        )}
      </div>
      <div className="flex-1 overflow-auto">
        {vmProcessTree.length === 0 ? (
          <EmptyState message="No processes observed" submessage="Start a VM sandbox to see the process tree" />
        ) : (
          vmProcessTree.map((node) => (
            <ProcessNodeRow key={node.pid} node={node} depth={0} collapsed={collapsed} onToggle={onToggle} />
          ))
        )}
      </div>
    </div>
  );
}
