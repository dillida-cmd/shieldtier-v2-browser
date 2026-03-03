import { useStore } from '../../store';
import type { ProcessNode } from '../../ipc/types';

function ProcessNodeRow({ node, depth }: { node: ProcessNode; depth: number }) {
  return (
    <>
      <div className="flex items-center gap-1 px-2 py-0.5 hover:bg-[var(--st-bg-hover)] transition-colors font-mono text-[11px]" style={{ paddingLeft: `${8 + depth * 16}px` }}>
        {node.children.length > 0 ? <span className="text-[var(--st-text-muted)]">&#9658;</span> : <span className="text-[var(--st-border)] ml-1.5">&middot;</span>}
        <span className="text-[var(--st-severity-clean)]">{node.name}</span>
        <span className="text-[var(--st-text-muted)] text-[9px]">pid={node.pid}</span>
      </div>
      {node.children.map((child) => <ProcessNodeRow key={child.pid} node={child} depth={depth + 1} />)}
    </>
  );
}

export function ProcessPanel() {
  const { vmProcessTree } = useStore();
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Process Tree</span>
      </div>
      <div className="flex-1 overflow-auto">
        {vmProcessTree.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No processes observed</div>
        ) : (
          vmProcessTree.map((node) => <ProcessNodeRow key={node.pid} node={node} depth={0} />)
        )}
      </div>
    </div>
  );
}
