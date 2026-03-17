/**
 * Shared helper functions used across multiple panel components.
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import type { HAREntry, IOCEntry } from '../../types';
import type { DomainCategory } from './panel-types';

// ═══════════════════════════════════════════════════════
// Network helpers
// ═══════════════════════════════════════════════════════

export function extractPath(url: string): string {
  try { return new URL(url).pathname + new URL(url).search; } catch { return url; }
}

export function extractHost(url: string): string {
  try { return new URL(url).host; } catch { return ''; }
}

export function formatNetSize(bytes: number): string {
  if (bytes <= 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatNetTime(ms: number): string {
  if (ms <= 0) return '-';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function getStatusColor(status: number): string {
  if (status === 0) return 'text-gray-500';
  if (status < 300) return 'text-green-400';
  if (status < 400) return 'text-blue-400';
  if (status < 500) return 'text-yellow-400';
  return 'text-red-400';
}

export function getMethodColor(method: string): string {
  switch (method) {
    case 'GET': return 'text-blue-400';
    case 'POST': return 'text-green-400';
    case 'PUT': return 'text-yellow-400';
    case 'DELETE': return 'text-red-400';
    case 'PATCH': return 'text-purple-400';
    default: return 'text-gray-400';
  }
}

function inferResourceType(mime: string): string {
  if (!mime) return 'Other';
  const m = mime.toLowerCase();
  if (m === 'text/html' || m === 'application/xhtml+xml') return 'Document';
  if (m.includes('javascript') || m === 'application/x-javascript') return 'Script';
  if (m === 'text/css') return 'Stylesheet';
  if (m.startsWith('font/') || m === 'application/font-woff' || m === 'application/font-woff2' || m.includes('opentype')) return 'Font';
  if (m.startsWith('image/')) return 'Image';
  if (m.startsWith('video/') || m.startsWith('audio/')) return 'Media';
  if (m === 'application/json' || m === 'text/xml' || m === 'application/xml' || m.includes('+json') || m.includes('+xml')) return 'XHR';
  return 'Other';
}

export function categorizeDomain(domain: string, entries: HAREntry[]): DomainCategory {
  const ld = domain.toLowerCase();

  // Layer 1 — Known domain patterns
  if (['doubleclick', 'googlesyndication', 'googleadservices', 'adservice.google', 'ogads', 'adsense'].some(p => ld.includes(p))) return 'ads';
  if (['google-analytics', 'googletagmanager', 'analytics', 'hotjar', 'segment.'].some(p => ld.includes(p))) return 'analytics';
  if (['fonts.googleapis.com', 'fonts.gstatic.com', 'use.typekit.net'].some(p => ld.includes(p))) return 'font';
  if (['cdn.', 'cloudfront', 'cloudflare', 'fastly', 'akamai', 'jsdelivr', 'unpkg'].some(p => ld.includes(p))) return 'cdn';

  // Layer 2 — resourceType (direct or inferred from MIME)
  const typeCounts = new Map<string, number>();
  for (const entry of entries) {
    let rt = entry.resourceType;
    if (!rt || rt === 'Other') {
      rt = inferResourceType(entry.response?.content?.mimeType || '');
    }
    typeCounts.set(rt, (typeCounts.get(rt) || 0) + 1);
  }
  let dominant = 'Other';
  let maxCount = 0;
  for (const [rt, count] of typeCounts) {
    if (count > maxCount) { dominant = rt; maxCount = count; }
  }
  switch (dominant) {
    case 'Document': return 'page';
    case 'Script': return 'script';
    case 'Stylesheet': return 'style';
    case 'Font': return 'font';
    case 'Image': return 'image';
    case 'Media': return 'media';
    case 'XHR': case 'Fetch': return 'api';
    default: return 'other';
  }
}

export function matchWildcardClient(pattern: string, domain: string): boolean {
  const lp = pattern.toLowerCase();
  const ld = domain.toLowerCase();
  if (lp === ld) return true;
  if (lp.startsWith('*.')) {
    const suffix = lp.slice(1);
    return ld.endsWith(suffix) || ld === lp.slice(2);
  }
  return false;
}

export const BUILT_IN_PATTERNS = [
  '*.googleapis.com', '*.gstatic.com', '*.google.com',
  '*.cloudflare.com', '*.cloudflareinsights.com',
  '*.amazonaws.com', '*.cloudfront.net',
  '*.jquery.com', '*.bootstrapcdn.com',
  '*.fontawesome.com', 'fonts.googleapis.com',
];

// ═══════════════════════════════════════════════════════
// IOC / Analysis helpers
// ═══════════════════════════════════════════════════════

export function getOverallVerdict(entry: IOCEntry): string {
  if (entry.status === 'skipped') return 'unknown';
  const verdicts = entry.results.filter(r => r.verdict !== 'error' && r.verdict !== 'unknown');
  if (verdicts.some(r => r.verdict === 'malicious')) return 'malicious';
  if (verdicts.some(r => r.verdict === 'suspicious')) return 'suspicious';
  if (verdicts.length > 0) return 'clean';
  if (entry.status === 'pending' || entry.status === 'enriching') return 'unknown';
  return 'unknown';
}

export function extractHostFromURL(url: string): string {
  try { return new URL(url).hostname.toLowerCase(); } catch { return url; }
}

// ═══════════════════════════════════════════════════════
// File helpers
// ═══════════════════════════════════════════════════════

export function formatFileSize(bytes: number): string {
  if (bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ═══════════════════════════════════════════════════════
// Shared color/label constants
// ═══════════════════════════════════════════════════════

export const VERDICT_COLORS: Record<string, { dot: string; text: string; bg: string; border: string }> = {
  malicious:  { dot: 'bg-red-500',    text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30' },
  suspicious: { dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
  clean:      { dot: 'bg-green-500',  text: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30' },
  unknown:    { dot: 'bg-gray-500',   text: 'text-gray-400',   bg: 'bg-gray-500/10',   border: 'border-gray-500/30' },
  error:      { dot: 'bg-gray-600',   text: 'text-gray-500',   bg: 'bg-gray-600/10',   border: 'border-gray-600/30' },
};

export const PROVIDER_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb:  'AbuseIPDB',
  otx:        'OTX',
  urlhaus:    'URLhaus',
  whois:      'WHOIS',
};

export const CATEGORY_CONFIG: Record<DomainCategory, { label: string; color: string }> = {
  page:      { label: 'Page',      color: 'text-[color:var(--st-info)] bg-[color:var(--st-info-dim)] border-blue-400/20' },
  script:    { label: 'Script',    color: 'text-[color:var(--st-warning)] bg-[color:var(--st-warning-dim)] border-yellow-400/20' },
  style:     { label: 'Style',     color: 'text-purple-400 bg-purple-400/10 border-purple-400/20' },
  font:      { label: 'Font',      color: 'text-pink-400 bg-pink-400/10 border-pink-400/20' },
  image:     { label: 'Image',     color: 'text-[color:var(--st-success)] bg-[color:var(--st-success-dim)] border-green-400/20' },
  media:     { label: 'Media',     color: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20' },
  api:       { label: 'API',       color: 'text-orange-400 bg-orange-400/10 border-orange-400/20' },
  ads:       { label: 'Ads',       color: 'text-[color:var(--st-danger)] bg-[color:var(--st-danger-dim)] border-red-400/20' },
  analytics: { label: 'Analytics', color: 'text-amber-400 bg-amber-400/10 border-amber-400/20' },
  cdn:       { label: 'CDN',       color: 'text-teal-400 bg-teal-400/10 border-teal-400/20' },
  other:     { label: 'Other',     color: 'text-gray-400 bg-gray-400/10 border-gray-400/20' },
};

export const STATUS_LABELS: Record<string, string> = {
  downloading: 'Downloading...',
  hashing: 'Computing hashes...',
  analyzing: 'Static analysis...',
  enriching: 'Hash enrichment...',
  submitting: 'Behavioral analysis...',
  'password-required': 'Password required',
  extracting: 'Extracting...',
  complete: 'Complete',
  error: 'Error',
};

export const SANDBOX_LABELS: Record<string, string> = {
  inline: 'ShieldTier Behavioral Engine',
  vm: 'ShieldTier VM Sandbox',
  virustotal: 'VirusTotal',
  hybridanalysis: 'Hybrid Analysis',
  joesandbox: 'Joe Sandbox',
  cuckoo: 'Cuckoo Sandbox',
};

export const SEVERITY_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: 'bg-red-600/20', text: 'text-red-400', dot: 'bg-red-500' },
  high: { bg: 'bg-orange-600/20', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium: { bg: 'bg-yellow-600/20', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  low: { bg: 'bg-blue-600/20', text: 'text-blue-400', dot: 'bg-blue-500' },
  info: { bg: 'bg-gray-600/20', text: 'text-gray-400', dot: 'bg-gray-500' },
};

export const CATEGORY_LABELS: Record<string, string> = {
  eval_obfuscation: 'Eval/Obfuscation',
  hidden_content: 'Hidden Content',
  credential_harvest: 'Credential Harvest',
  crypto_mining: 'Crypto Mining',
  base64_payload: 'Base64 Payload',
  suspicious_redirect: 'Suspicious Redirect',
  external_script: 'External Script',
  data_exfil: 'Data Exfiltration',
};

export const TYPE_SECTION_LABELS: Record<import('../../types').IOCType, string> = {
  domain: 'Domains',
  ip: 'IP Addresses',
  url: 'URLs',
  hash: 'Hashes',
};

export const TYPE_SECTION_ORDER: import('../../types').IOCType[] = ['domain', 'ip', 'url', 'hash'];

export const SEVERITY_ORDER: import('../../types').ContentFindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
