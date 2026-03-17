/**
 * Shared type definitions used by both main and renderer processes.
 * Single source of truth to avoid duplicate type definitions.
 */

export interface ProxyConfig {
  host: string;
  port: number;
  type: 'socks5' | 'http' | 'direct';
  username?: string;
  password?: string;
  region?: string;
}

export interface InvestigationSession {
  id: string;
  caseId: string;
  createdAt: number;
  caseName?: string;
  url?: string;
  proxyConfig?: ProxyConfig;
  partition: string;
}

export interface NavigationState {
  url: string;
  title: string;
  isLoading: boolean;
  canGoBack: boolean;
  canGoForward: boolean;
}
