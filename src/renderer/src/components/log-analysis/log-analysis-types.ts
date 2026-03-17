// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Shared Types
// ---------------------------------------------------------------------------
// Mirrored from main/loganalysis/types.ts — renderer cannot import directly.
// ---------------------------------------------------------------------------

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface NormalizedEvent {
  timestamp: string;
  source: string;
  eventType: string;
  severity: Severity;
  category: string;
  message: string;
  raw: string;
  metadata: Record<string, unknown>;
}

export interface LogInsight {
  level: 'info' | 'warning' | 'danger';
  title: string;
  detail: string;
}

export interface TriageEntity {
  value: string;
  count: number;
  severity: Severity;
  context: string;
}

export interface AttackPhase {
  phase: string;
  events: number;
  indicators: string[];
}

export interface LogTriage {
  incident: { severity: Severity; score: number };
  entities: {
    users: TriageEntity[];
    ips: TriageEntity[];
    hosts: TriageEntity[];
    processes: TriageEntity[];
    commands: TriageEntity[];
    externalIps: TriageEntity[];
  };
  attackChain: AttackPhase[];
}

export interface InvestigationChain {
  type: 'authentication' | 'process' | 'network' | 'lateral_movement' | 'file_access';
  title: string;
  events: NormalizedEvent[];
  severity: Severity;
}

export interface LogInvestigation {
  chains: InvestigationChain[];
}

export interface GraphNode {
  id: string;
  type: 'user' | 'ip' | 'host' | 'process' | 'subprocess' | 'file';
  label: string;
  severity?: Severity;
  eventCount?: number;
  mitre?: string[];
  reason?: string;
  phases?: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  count: number;
  severity?: Severity;
}

export interface LogGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface VerdictSignal {
  title: string;
  severity: Severity;
  evidence: string;
  mitre?: string;
}

export interface LogVerdict {
  verdict: 'clean' | 'suspicious' | 'compromised' | 'critical';
  confidence: number;
  signals: VerdictSignal[];
  falsePositives: string[];
  killChain: string[];
  reasoning: string;
}

export interface HuntingQuery {
  id: string;
  name: string;
  description: string;
  mitre: string;
  category: string;
  severity: Severity;
  source: string;
}

export interface HuntingMatch {
  event: NormalizedEvent;
  evidence: string;
}

export interface HuntingQueryResult {
  query: HuntingQuery;
  matches: HuntingMatch[];
  matchCount: number;
}

export interface LogAnalysisResult {
  id: string;
  sessionId: string;
  fileName: string;
  format: string;
  eventCount: number;
  parseErrors: number;
  severityCounts: Record<Severity, number>;
  categoryCounts: Record<string, number>;
  events: NormalizedEvent[];
  insights: LogInsight[];
  triage: LogTriage | null;
  investigation: LogInvestigation | null;
  graph: LogGraph | null;
  verdict: LogVerdict | null;
  hunting: HuntingQueryResult[] | null;
  status: 'pending' | 'analyzing' | 'complete' | 'error';
  error?: string;
  startedAt: number;
  completedAt?: number;
}

export interface SupportedFormat {
  id: string;
  name: string;
  extensions: string[];
}

export type SubTab = 'overview' | 'events' | 'triage' | 'investigation' | 'graph' | 'verdict' | 'hunting';

export interface ProcessTreeNode {
  name: string;
  pid: string;
  commandLine: string;
  actionType: string;
  timestamp: string;
  severity: Severity;
  children: ProcessTreeNode[];
}

export interface NodePos {
  id: string;
  x: number;
  y: number;
  type: string;
  label: string;
  severity?: Severity;
  eventCount?: number;
  mitre?: string[];
  reason?: string;
  phases?: string[];
}

export interface AggregatedGroup {
  message: string;
  severity: Severity;
  count: number;
  firstTs: string;
  lastTs: string;
  /** One representative event per group (for expanding raw details). */
  representative: NormalizedEvent;
}
