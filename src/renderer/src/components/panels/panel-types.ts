/**
 * Shared types used across multiple panel components.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

export interface TimelineEvent {
  time: string;
  event: string;
  detail: string;
  type: 'info' | 'warning' | 'danger';
}

export type NetworkViewMode = 'flat' | 'grouped';

export type DomainCategory = 'page' | 'script' | 'style' | 'font' | 'image' | 'media' | 'api' | 'ads' | 'analytics' | 'cdn' | 'other';

export interface DomainGroup {
  domain: string;
  entries: import('../../types').HAREntry[];
  totalSize: number;
  errorCount: number;
  isWhitelisted: boolean;
  category: DomainCategory;
}

export interface IOCGroup {
  key: string;
  label: string;
  entries: import('../../types').IOCEntry[];
  safe: boolean;
  overallVerdict: string;
}

export interface TypeSection {
  type: import('../../types').IOCType;
  label: string;
  groups: IOCGroup[];
  count: number;
}
