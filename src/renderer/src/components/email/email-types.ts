// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Shared Types
// ---------------------------------------------------------------------------
// Mirrored from main process — renderer cannot import directly.
// ---------------------------------------------------------------------------

export interface ReceivedHop {
  from: string;
  by: string;
  timestamp: number;
  delay: number;
  ip: string;
}

export interface AuthenticationResult {
  method: 'spf' | 'dkim' | 'dmarc';
  result: string;
  domain: string;
}

export interface EmailAttachment {
  id: string;
  filename: string;
  contentType: string;
  size: number;
  quarantineFileId?: string;
  extracted: boolean;
}

export interface ExtractedURL {
  url: string;
  displayText: string;
  mismatch: boolean;
  source: 'html' | 'text' | 'header';
  redirectError?: string;
}

export interface PhishingIndicator {
  id: string;
  category: string;
  severity: string;
  description: string;
  evidence: string;
  mitre?: string;
}

export interface PhishingScore {
  score: number;
  verdict: string;
  indicators: PhishingIndicator[];
  breakdown: Record<string, number>;
}

export interface ParsedEmail {
  id: string;
  sessionId: string;
  from: string;
  to: string[];
  cc: string[];
  subject: string;
  date: string;
  headers: Record<string, string>;
  receivedChain: ReceivedHop[];
  authentication: AuthenticationResult[];
  textBody: string;
  htmlBody: string;
  urls: ExtractedURL[];
  attachments: EmailAttachment[];
  phishingScore: PhishingScore | null;
  rawSource: string;
  parsedAt: number;
}

export interface FileAnalysisResult {
  id: string;
  originalName: string;
  fileSize: number;
  status: string;
  riskLevel: string;
  hashes: { md5: string; sha1: string; sha256: string } | null;
  staticAnalysis: {
    fileType: string;
    mimeType: string;
    entropy: number;
    findings: { severity: string; category: string; description: string; mitre?: string }[];
    metadata: Record<string, any>;
  } | null;
  sandboxResults: {
    provider: string;
    status: string;
    verdict?: string;
    score?: number;
    details: Record<string, any>;
  }[];
  behavioralAnalysisDone?: boolean;
  behavioralAnalysisRunning?: boolean;
}
