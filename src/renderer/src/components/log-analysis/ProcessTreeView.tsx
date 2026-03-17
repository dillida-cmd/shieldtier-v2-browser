// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Process Tree Visualization
// ---------------------------------------------------------------------------

import React from 'react';
import type { Severity, ProcessTreeNode } from './log-analysis-types';
import { SEVERITY_TEXT_COLOR, PTREE_ROW_BG } from './log-analysis-utils';
import { cn } from '../../lib/utils';
import { Badge } from '../ui/badge';

export function ProcessTreeNodeView({ node, depth }: { node: ProcessTreeNode; depth: number }) {
  const [cmdExpanded, setCmdExpanded] = React.useState(false);
  const cmdTruncLen = 80;
  const cmdLong = node.commandLine.length > cmdTruncLen;

  const rowBg = PTREE_ROW_BG[node.severity] || PTREE_ROW_BG.info;

  // Format PID as hex + decimal when available
  const pidNum = node.pid ? parseInt(node.pid, 10) : NaN;
  const pidDisplay = !isNaN(pidNum)
    ? `PID: 0x${pidNum.toString(16)} (${pidNum})`
    : node.pid ? `PID: ${node.pid}` : '';

  return (
    <div>
      <div
        className={cn(rowBg, 'border-l-2 rounded-r px-3 py-1.5 mb-0.5')}
        style={{ marginLeft: depth * 28 }}
      >
        <div className="flex items-center justify-between gap-2">
          <span className={cn('font-semibold text-[11px] font-mono', SEVERITY_TEXT_COLOR[node.severity])}>
            {node.name}
          </span>
          <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono shrink-0">
            {pidDisplay}
          </span>
        </div>
        {node.commandLine && (
          <div
            className={cn(
              'font-mono text-[10px] text-[color:var(--st-text-muted)] mt-0.5 leading-snug',
              cmdExpanded ? 'break-all' : 'truncate'
            )}
            onClick={cmdLong ? () => setCmdExpanded(!cmdExpanded) : undefined}
            style={cmdLong ? { cursor: 'pointer' } : undefined}
            title={cmdLong ? (cmdExpanded ? 'Click to collapse' : 'Click to expand') : undefined}
          >
            {cmdExpanded || !cmdLong ? node.commandLine : node.commandLine.slice(0, cmdTruncLen) + '\u2026'}
          </div>
        )}
      </div>
      {node.children.map((child, i) => (
        <ProcessTreeNodeView key={`${depth}-${i}`} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}
