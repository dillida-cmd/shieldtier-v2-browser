export type IpcAction =
  | 'navigate'
  | 'get_tabs'
  | 'close_tab'
  | 'analyze_download'
  | 'get_analysis_result'
  | 'get_config'
  | 'set_config'
  | 'export_report'
  | 'get_threat_feeds'
  | 'start_capture'
  | 'stop_capture'
  | 'get_capture'
  | 'start_vm'
  | 'stop_vm'
  | 'submit_sample_to_vm'
  | 'nav_back'
  | 'nav_forward'
  | 'nav_reload'
  | 'nav_stop';

export interface IpcResponse<T = unknown> {
  success: boolean;
  data: T;
  error?: string;
}

export interface TabInfo {
  tab_id: string;
  browser_id: number;
  in_memory: boolean;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  title: string;
  description: string;
  severity: SeverityLevel;
  engine: string;
  metadata: Record<string, unknown>;
}

export interface ThreatVerdict {
  score: number;
  severity: SeverityLevel;
  label: string;
  findings: Finding[];
  engine_summaries: Record<string, unknown>;
}

export interface AnalysisResult {
  status: 'pending' | 'complete' | 'error' | 'not_found';
  verdict?: ThreatVerdict;
  error?: string;
}

export interface CaptureData {
  capturing: boolean;
  request_count: number;
  har: string;
}

export interface HarEntry {
  method: string;
  url: string;
  status: number;
  size: number;
  time: number;
  mimeType: string;
}

export interface HarLog {
  log: {
    entries: Array<{
      request: { method: string; url: string };
      response: { status: number; content: { size: number; mimeType: string } };
      time: number;
    }>;
  };
}

export type VmStatus = 'idle' | 'booting' | 'running' | 'complete' | 'error';

export interface VmEvent {
  timestamp: string;
  category: string;
  action: string;
  detail: string;
  severity?: SeverityLevel;
}

export interface ProcessNode {
  pid: number;
  name: string;
  children: ProcessNode[];
}

export interface NetworkSummary {
  dns_query_count: number;
  http_request_count: number;
  connection_count: number;
}

export interface DownloadInfo {
  sha256: string;
  filename: string;
  size: number;
}

export interface FileEntry {
  filename: string;
  sha256: string;
  size: number;
  mimeType: string;
  path: string;
  severity?: SeverityLevel;
}
