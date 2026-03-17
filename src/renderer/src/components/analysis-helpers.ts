/**
 * Shared constants and helpers for sandbox analysis report panel.
 * Extracted from Workspace.tsx to allow reuse across components.
 */

export const CATEGORY_META: Record<string, { color: string; bg: string; desc: string }> = {
  NETWORK:     { color: 'text-blue-400',   bg: 'bg-blue-400/15',   desc: 'Network connections & downloads' },
  FILE:        { color: 'text-cyan-400',    bg: 'bg-cyan-400/15',    desc: 'File read/write/delete operations' },
  REGISTRY:    { color: 'text-yellow-400',  bg: 'bg-yellow-400/15',  desc: 'Windows registry modifications' },
  PROCESS:     { color: 'text-orange-400',  bg: 'bg-orange-400/15',  desc: 'Process creation & manipulation' },
  INJECTION:   { color: 'text-red-400',     bg: 'bg-red-400/15',     desc: 'Code injection into other processes' },
  CRYPTO:      { color: 'text-purple-400',  bg: 'bg-purple-400/15',  desc: 'Encryption & decryption routines' },
  EVASION:     { color: 'text-red-300',     bg: 'bg-red-300/15',     desc: 'Anti-analysis & evasion techniques' },
  PERSISTENCE: { color: 'text-amber-400',   bg: 'bg-amber-400/15',   desc: 'Auto-start & persistence mechanisms' },
  INFORMATION: { color: 'text-teal-400',    bg: 'bg-teal-400/15',    desc: 'System & user data collection' },
  PRIVILEGE:   { color: 'text-rose-400',    bg: 'bg-rose-400/15',    desc: 'Privilege escalation attempts' },
  SERVICE:     { color: 'text-indigo-400',  bg: 'bg-indigo-400/15',  desc: 'Windows service interaction' },
  HOOKING:     { color: 'text-pink-400',    bg: 'bg-pink-400/15',    desc: 'System function hooking' },
  UNKNOWN:     { color: 'text-gray-400',    bg: 'bg-gray-500/15',    desc: 'Unclassified API imports' },
};

export const OP_LABELS: Record<string, string> = {
  file_write: 'Write', file_read: 'Read', file_delete: 'Delete', file_execute: 'Execute',
  registry_read: 'Reg Read', registry_write: 'Reg Write', registry_delete: 'Reg Delete',
  network_request: 'HTTP', process_execute: 'Exec', process_create: 'Spawn',
  environment_read: 'Env', wmi_query: 'WMI', com_create: 'COM',
  shell_command: 'Shell', download: 'Download', dns_resolve: 'DNS',
};

export const RISK_COLORS: Record<string, { dot: string; text: string; bg: string }> = {
  critical: { dot: 'bg-red-600',    text: 'text-red-400',    bg: 'bg-red-600/10' },
  high:     { dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10' },
  medium:   { dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  low:      { dot: 'bg-blue-400',   text: 'text-blue-400',   bg: 'bg-blue-400/10' },
  info:     { dot: 'bg-green-500',  text: 'text-green-400',  bg: 'bg-green-500/10' },
  unknown:  { dot: 'bg-gray-500',   text: 'text-gray-400',   bg: 'bg-gray-500/10' },
};

export const MITRE_MAP: Record<string, string> = {
  INJECTION: 'T1055', PROCESS: 'T1059', PERSISTENCE: 'T1547', EVASION: 'T1027',
  PRIVILEGE: 'T1548', NETWORK: 'T1071', CRYPTO: 'T1486', REGISTRY: 'T1112',
  FILE: 'T1005', INFORMATION: 'T1082', SERVICE: 'T1543', HOOKING: 'T1056',
};

export interface ProcessTreeNode {
  name: string;
  cmdline: string;
  type?: string;
  source?: 'detonation' | 'emulation';
  children: ProcessTreeNode[];
}

export function buildProcessTree(
  filename: string,
  detOps: { type: string; target: string; data?: string }[],
  emuCalls: { name: string; args: string[]; returnValue: number }[],
): ProcessTreeNode {
  const root: ProcessTreeNode = { name: filename, cmdline: `"${filename}"`, children: [] };

  // Add process-spawning operations from detonation
  for (const op of detOps) {
    if (!['process_execute', 'process_create', 'shell_command'].includes(op.type)) continue;
    const name = op.target.split(/[/\\]/).pop() || op.target;
    const child: ProcessTreeNode = {
      name,
      cmdline: `${name}${op.data ? ' ' + op.data : ''}`,
      type: op.type,
      source: 'detonation',
      children: [],
    };
    if ((name.toLowerCase() === 'cmd.exe' || name.toLowerCase() === 'cmd') && op.data) {
      const inner = op.data.match(/(?:powershell|wscript|cscript|mshta|regsvr32|rundll32|msiexec|certutil)(?:\.exe)?/i);
      if (inner) {
        const innerName = inner[0].includes('.') ? inner[0] : inner[0] + '.exe';
        child.children.push({ name: innerName, cmdline: op.data, source: 'detonation', children: [] });
      }
    }
    root.children.push(child);
  }

  // Add process-creation API calls from shellcode emulation
  const processApis = ['CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessInternalW'];
  for (const call of emuCalls) {
    if (!processApis.includes(call.name)) continue;
    const arg = call.args?.[0] || call.name;
    const name = arg.split(/[/\\]/).pop() || arg;
    root.children.push({ name: name || call.name, cmdline: call.args?.join(' ') || call.name, type: 'emu_' + call.name, source: 'emulation', children: [] });
  }

  return root;
}

export function countTreeNodes(node: ProcessTreeNode): number {
  return 1 + node.children.reduce((sum, c) => sum + countTreeNodes(c), 0);
}

export function treeDepth(node: ProcessTreeNode): number {
  if (node.children.length === 0) return 0;
  return 1 + Math.max(...node.children.map(treeDepth));
}

/** Format bytes to human-readable string */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
