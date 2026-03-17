// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Shared Utilities, Constants & Helpers
// ---------------------------------------------------------------------------

import type {
  Severity,
  NormalizedEvent,
  InvestigationChain,
  ProcessTreeNode,
  GraphNode,
  NodePos,
  AggregatedGroup,
} from './log-analysis-types';

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

export const EVENTS_PER_PAGE = 50;

export const SEVERITY_COLORS: Record<Severity, string> = {
  info: 'bg-blue-500/10 text-blue-400',
  low: 'bg-green-500/10 text-green-400',
  medium: 'bg-yellow-500/10 text-yellow-400',
  high: 'bg-orange-500/10 text-orange-400',
  critical: 'bg-red-500/10 text-red-400',
};

export const SEVERITY_DOT: Record<Severity, string> = {
  info: 'bg-blue-400',
  low: 'bg-green-400',
  medium: 'bg-yellow-400',
  high: 'bg-orange-400',
  critical: 'bg-red-400',
};

export const VERDICT_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  clean:        { bg: 'bg-green-500/15',  text: 'text-green-400',  border: 'border-green-500/30' },
  suspicious:   { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  compromised:  { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30' },
  critical:     { bg: 'bg-red-500/15',    text: 'text-red-400',    border: 'border-red-500/30' },
};

export const INSIGHT_BORDER: Record<string, string> = {
  danger:  'border-l-red-500',
  warning: 'border-l-orange-500',
  info:    'border-l-blue-500',
};

export const CHAIN_TYPE_ICONS: Record<string, string> = {
  authentication: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z',
  process: 'M20 3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H4V5h16v14zm-6-4h2v2h-2v-2zm-8 0h6v2H6v-2zm8-4h2v2h-2v-2zm-8 0h6v2H6v-2z',
  network: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z',
  lateral_movement: 'M6.99 11L3 15l3.99 4v-3H14v-2H6.99v-3zM21 9l-3.99-4v3H10v2h7.01v3L21 9z',
  file_access: 'M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z',
};

export const ATTACK_PHASE_COLORS: Record<string, string> = {
  'reconnaissance':     'bg-blue-500/20 text-blue-400 border-blue-500/30',
  'initial-access':     'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  'execution':          'bg-purple-500/20 text-purple-400 border-purple-500/30',
  'persistence':        'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  'privilege-escalation': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  'defense-evasion':    'bg-pink-500/20 text-pink-400 border-pink-500/30',
  'credential-access':  'bg-red-500/20 text-red-400 border-red-500/30',
  'discovery':          'bg-teal-500/20 text-teal-400 border-teal-500/30',
  'lateral-movement':   'bg-amber-500/20 text-amber-400 border-amber-500/30',
  'collection':         'bg-lime-500/20 text-lime-400 border-lime-500/30',
  'exfiltration':       'bg-rose-500/20 text-rose-400 border-rose-500/30',
  'command-and-control': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  'impact':             'bg-red-600/20 text-red-500 border-red-600/30',
};

export const SEVERITY_TEXT_COLOR: Record<Severity, string> = {
  info: 'text-blue-400',
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
  critical: 'text-red-400',
};

/** Row background colour keyed by severity — mirrors the reference process-tree look. */
export const PTREE_ROW_BG: Record<Severity, string> = {
  info:     'bg-slate-600/30 border-l-slate-400',
  low:      'bg-emerald-900/30 border-l-emerald-400',
  medium:   'bg-yellow-900/30 border-l-yellow-400',
  high:     'bg-red-900/30 border-l-red-400',
  critical: 'bg-red-800/40 border-l-red-500',
};

export const NODE_COLORS: Record<string, { fill: string; stroke: string }> = {
  user:       { fill: '#3b82f6', stroke: '#60a5fa' },
  ip:         { fill: '#22c55e', stroke: '#4ade80' },
  host:       { fill: '#a855f7', stroke: '#c084fc' },
  process:    { fill: '#f97316', stroke: '#fb923c' },
  subprocess: { fill: '#fb923c', stroke: '#fdba74' },
  file:       { fill: '#eab308', stroke: '#facc15' },
};

export const SEVERITY_LEVELS: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const SEVERITY_INDEX: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const ENTITY_TYPES = ['host', 'user', 'process', 'subprocess', 'ip', 'file'] as const;

export const SEV_BUTTON_STYLES: Record<Severity, { active: string; inactive: string }> = {
  info:     { active: 'bg-gray-600 text-white', inactive: 'text-gray-500 hover:text-gray-300' },
  low:      { active: 'bg-blue-600 text-white', inactive: 'text-blue-500/60 hover:text-blue-400' },
  medium:   { active: 'bg-yellow-600 text-white', inactive: 'text-yellow-500/60 hover:text-yellow-400' },
  high:     { active: 'bg-orange-600 text-white', inactive: 'text-orange-500/60 hover:text-orange-400' },
  critical: { active: 'bg-red-600 text-white', inactive: 'text-red-500/60 hover:text-red-400' },
};

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

export function getSeverityBadge(severity: Severity): string {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
}

export function getVerdictStyle(verdict: string) {
  return VERDICT_COLORS[verdict] || VERDICT_COLORS.clean;
}

export function getPhaseColor(phase: string): string {
  return ATTACK_PHASE_COLORS[phase] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
}

export function truncate(text: string, len: number): string {
  return text.length > len ? text.slice(0, len) + '...' : text;
}

export function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return ts;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Investigation Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Safe metadata value extractor — handles spaced and camelCase field names. */
export function metaVal(m: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = m[k];
    if (v !== undefined && v !== null && v !== '' && v !== '-') return String(v);
  }
  return '';
}

/** Extract basename from a path (handles both \ and /). */
export function baseName(path: string): string {
  if (!path) return '';
  return path.replace(/\\/g, '/').split('/').pop() || path;
}

/** Extract root entity label for chain header */
export function extractRootEntity(chain: InvestigationChain): string {
  const first = chain.events[0];
  if (!first) return chain.title;
  const m = first.metadata as Record<string, unknown>;
  if (chain.type === 'process') {
    const proc = metaVal(m, '_process', 'Image', 'ProcessName', 'File Name', 'FileName');
    return baseName(proc) || chain.title;
  }
  if (chain.type === 'authentication') return metaVal(m, '_user', 'TargetUserName', 'User', 'user', 'Account Name', 'AccountName') || chain.title;
  if (chain.type === 'network') {
    // Prefer process name for network chains (e.g. "TeamViewer_Service.exe")
    const proc = metaVal(m, '_process', 'Image', 'ProcessName', 'File Name', 'FileName');
    const procName = baseName(proc);
    if (procName) return procName;
    // Fallback to source IP
    return metaVal(m, '_src_ip', 'SourceIP', 'src_ip', 'SourceAddress', 'Local IP', 'LocalIP') || chain.title;
  }
  if (chain.type === 'lateral_movement') return metaVal(m, '_user', 'TargetUserName', 'User', 'user', 'Account Name', 'AccountName') || chain.title;
  if (chain.type === 'file_access') {
    const proc = metaVal(m, '_process', 'Image', 'ProcessName', 'File Name', 'FileName');
    return baseName(proc) || chain.title;
  }
  return chain.title;
}

export function extractHost(chain: InvestigationChain): string {
  for (const evt of chain.events) {
    const m = evt.metadata as Record<string, unknown>;
    const h = metaVal(m, '_host', 'Computer', 'Computer Name', 'ComputerName', 'Hostname', 'hostname', 'host', 'DeviceName', 'Workstation');
    if (h) return h;
  }
  return '';
}

export function extractUser(chain: InvestigationChain): string {
  for (const evt of chain.events) {
    const m = evt.metadata as Record<string, unknown>;
    const u = metaVal(m, '_user', 'TargetUserName', 'User', 'user', 'Account Name', 'AccountName', 'SubjectUserName', 'Initiating Process Account Name');
    if (u) return u;
  }
  return '';
}

/** Extract network connection summary for network chain headers. */
export function extractNetworkSummary(chain: InvestigationChain): string {
  const srcIps = new Set<string>();
  const dstIps = new Set<string>();
  const procs = new Set<string>();
  for (const evt of chain.events) {
    const m = evt.metadata as Record<string, unknown>;
    const src = metaVal(m, '_src_ip', 'SourceIP', 'src_ip', 'SourceAddress', 'Local IP', 'LocalIP');
    const dst = metaVal(m, '_dst_ip', 'DestinationIP', 'dst_ip', 'DestinationAddress', 'Remote IP', 'RemoteIP');
    const proc = baseName(metaVal(m, '_process', 'Image', 'ProcessName', 'File Name', 'FileName'));
    if (src) srcIps.add(src);
    if (dst) dstIps.add(dst);
    if (proc) procs.add(proc);
  }
  const parts: string[] = [];
  if (srcIps.size > 0) parts.push(srcIps.size === 1 ? Array.from(srcIps)[0] : `${srcIps.size} sources`);
  if (dstIps.size > 0) parts.push(dstIps.size === 1 ? Array.from(dstIps)[0] : `${dstIps.size} destinations`);
  if (parts.length === 2) return `${parts[0]} \u2192 ${parts[1]}`;
  return parts.join(' | ');
}

// ═══════════════════════════════════════════════════════════════════════════
// Process Tree Builder
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Build a process tree from chain events using PID-based linking.
 * Each event is its own node — shows the actual spawn sequence stage by stage.
 * Falls back to name-based linking if PIDs are unavailable.
 */
export function buildProcessTree(events: NormalizedEvent[]): ProcessTreeNode[] {
  // Extract per-event data
  const nodes: Array<{
    name: string;
    pid: string;
    parentPid: string;
    parentName: string;
    cmdLine: string;
    actionType: string;
    timestamp: string;
    severity: Severity;
  }> = [];

  let hasPids = false;

  for (const evt of events) {
    const m = evt.metadata as Record<string, unknown>;
    const rawProc = metaVal(m, '_process', 'Image', 'ProcessName', 'File Name', 'FileName');
    const rawParent = metaVal(m, 'ParentImage', 'ParentProcessName', 'parent_process',
      'InitiatingProcessFileName', 'Initiating Process File Name');
    const pid = metaVal(m, 'Process Id', 'ProcessId', 'pid');
    const parentPid = metaVal(m, 'Initiating Process Id', 'InitiatingProcessId',
      'ParentProcessId', 'parent_pid');

    if (pid && parentPid) hasPids = true;

    nodes.push({
      name: baseName(rawProc) || evt.message.split(' ')[0] || 'unknown',
      pid,
      parentPid,
      parentName: baseName(rawParent),
      cmdLine: metaVal(m, '_command', 'CommandLine', 'ProcessCommandLine',
        'Process Command Line', 'command_line'),
      actionType: evt.eventType,
      timestamp: evt.timestamp,
      severity: evt.severity,
    });
  }

  // Sort by timestamp for chronological ordering
  nodes.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Build tree nodes
  const treeNodes = new Map<string, ProcessTreeNode>();
  const childList = new Map<string, ProcessTreeNode[]>();
  const hasParent = new Set<string>();

  if (hasPids) {
    // === PID-based tree: each event with unique PID is one node ===
    for (const n of nodes) {
      const key = n.pid || `${n.name}-${n.timestamp}`;
      if (treeNodes.has(key)) continue; // skip duplicate PIDs (keep first chronologically)

      const treeNode: ProcessTreeNode = {
        name: n.name,
        pid: n.pid,
        commandLine: n.cmdLine,
        actionType: n.actionType,
        timestamp: n.timestamp,
        severity: n.severity,
        children: [],
      };
      treeNodes.set(key, treeNode);

      const parentKey = n.parentPid || '__root__';
      if (!childList.has(parentKey)) childList.set(parentKey, []);
      childList.get(parentKey)!.push(treeNode);
      if (n.parentPid) hasParent.add(key);
    }

    // Link children to parents
    for (const [parentKey, children] of childList) {
      const parentNode = treeNodes.get(parentKey);
      if (parentNode) {
        parentNode.children.push(...children);
      }
    }

    // Find roots: nodes whose parentPid doesn't exist as a node
    const roots: ProcessTreeNode[] = [];
    for (const [key, node] of treeNodes) {
      if (!hasParent.has(key)) {
        // Check if this node's parent is in the tree
        const parentData = nodes.find(n => (n.pid || `${n.name}-${n.timestamp}`) === key);
        const parentPidKey = parentData?.parentPid || '';
        if (!parentPidKey || !treeNodes.has(parentPidKey)) {
          roots.push(node);
        }
      }
    }

    // If we found a valid tree, return it
    if (roots.length > 0) return roots;
  }

  // === Name-based fallback: group by parent->child name, each event its own node ===
  // Create a synthetic tree: group children under their parent name
  const rootNodes: ProcessTreeNode[] = [];
  const parentGroups = new Map<string, ProcessTreeNode>();

  for (const n of nodes) {
    const treeNode: ProcessTreeNode = {
      name: n.name,
      pid: n.pid,
      commandLine: n.cmdLine,
      actionType: n.actionType,
      timestamp: n.timestamp,
      severity: n.severity,
      children: [],
    };

    if (!n.parentName || n.parentName === n.name) {
      // Root-level node — check if we already have this parent as a group
      if (!parentGroups.has(n.name)) {
        parentGroups.set(n.name, treeNode);
        rootNodes.push(treeNode);
      } else {
        // Duplicate root name — add as sibling
        rootNodes.push(treeNode);
      }
    } else {
      // Has a parent — attach to parent group or create virtual parent
      if (!parentGroups.has(n.parentName)) {
        const virtualParent: ProcessTreeNode = {
          name: n.parentName,
          pid: '',
          commandLine: '',
          actionType: '',
          timestamp: n.timestamp,
          severity: 'info',
          children: [],
        };
        parentGroups.set(n.parentName, virtualParent);
        rootNodes.push(virtualParent);
      }
      parentGroups.get(n.parentName)!.children.push(treeNode);
      // Also register this node as a potential parent for deeper nesting
      if (!parentGroups.has(n.name)) {
        parentGroups.set(n.name, treeNode);
      }
    }
  }

  return rootNodes;
}

export function computeTreeDepth(nodes: ProcessTreeNode[]): number {
  if (nodes.length === 0) return 0;
  return 1 + Math.max(...nodes.map(n => computeTreeDepth(n.children)));
}

export function countTreeNodes(nodes: ProcessTreeNode[]): number {
  let count = nodes.length;
  for (const n of nodes) count += countTreeNodes(n.children);
  return count;
}

// ═══════════════════════════════════════════════════════════════════════════
// Aggregated Timeline
// ═══════════════════════════════════════════════════════════════════════════

export function aggregateEvents(events: NormalizedEvent[]): AggregatedGroup[] {
  if (events.length === 0) return [];
  const groups: AggregatedGroup[] = [];
  let current: AggregatedGroup | null = null;

  for (const evt of events) {
    if (current && current.message === evt.message) {
      current.count++;
      current.lastTs = evt.timestamp;
    } else {
      if (current) groups.push(current);
      current = {
        message: evt.message,
        severity: evt.severity,
        count: 1,
        firstTs: evt.timestamp,
        lastTs: evt.timestamp,
        representative: evt,
      };
    }
  }
  if (current) groups.push(current);
  return groups;
}

// ═══════════════════════════════════════════════════════════════════════════
// Graph Layout
// ═══════════════════════════════════════════════════════════════════════════

/** Pick smart default severity threshold based on what's in the graph. */
export function pickDefaultSeverity(nodes: GraphNode[]): Severity {
  const hasCritical = nodes.some(n => n.severity === 'critical');
  const hasHigh = nodes.some(n => n.severity === 'high');
  const hasMedium = nodes.some(n => n.severity === 'medium');
  if (hasCritical || hasHigh) return 'high';
  if (hasMedium) return 'medium';
  return 'info';
}

/** Column-based layout. Groups nodes by type into vertical columns. */
export function layoutNodes(nodes: GraphNode[]): { positions: NodePos[]; width: number; height: number; columns: { type: string; x: number }[] } {
  const COL_SPACING = 300;
  const ROW_SPACING = 80;
  const TOP_PAD = 50;
  const LEFT_PAD = 100;

  // Group by type
  const groups: Record<string, GraphNode[]> = {};
  for (const n of nodes) {
    if (!groups[n.type]) groups[n.type] = [];
    groups[n.type].push(n);
  }

  const typeOrder = ['host', 'user', 'process', 'subprocess', 'ip', 'file'];
  // Only include columns that have visible nodes
  const sortedTypes = typeOrder.filter(t => groups[t]);

  if (nodes.length === 1) {
    const n = nodes[0];
    const w = LEFT_PAD * 2 + COL_SPACING;
    const h = TOP_PAD + ROW_SPACING + 60;
    return {
      positions: [{
        id: n.id, type: n.type, label: n.label, severity: n.severity,
        eventCount: n.eventCount, mitre: n.mitre, reason: n.reason, phases: n.phases,
        x: w / 2, y: TOP_PAD + 30,
      }],
      width: w,
      height: h,
      columns: [{ type: n.type, x: w / 2 }],
    };
  }

  const positions: NodePos[] = [];
  const columns: { type: string; x: number }[] = [];
  let maxNodesInCol = 0;

  sortedTypes.forEach((type, colIdx) => {
    const group = groups[type];
    const colX = LEFT_PAD + colIdx * COL_SPACING;
    columns.push({ type, x: colX });
    if (group.length > maxNodesInCol) maxNodesInCol = group.length;

    group.forEach((node, rowIdx) => {
      positions.push({
        id: node.id,
        type: node.type,
        label: node.label,
        severity: node.severity,
        eventCount: node.eventCount,
        mitre: node.mitre,
        reason: node.reason,
        phases: node.phases,
        x: colX,
        y: TOP_PAD + rowIdx * ROW_SPACING + 30,
      });
    });
  });

  const width = Math.max(600, sortedTypes.length * COL_SPACING + LEFT_PAD + 80);
  const height = Math.max(400, maxNodesInCol * ROW_SPACING + TOP_PAD + 60);

  return { positions, width, height, columns };
}
