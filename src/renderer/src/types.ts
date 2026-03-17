export type SearchEngine = 'google' | 'brave' | 'bing';

export type { ProxyConfig, InvestigationSession, NavigationState } from './shared/types';

export interface LoadError {
  errorCode: number;
  errorDescription: string;
  url: string;
}

// ═══════════════════════════════════════════════════════
// Forensic Capture Types
// ═══════════════════════════════════════════════════════

export interface HAREntry {
  requestId: string;
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: { name: string; value: string }[];
    queryString: { name: string; value: string }[];
    postData?: { mimeType: string; text: string };
    headersSize: number;
    bodySize: number;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: { name: string; value: string }[];
    content: { size: number; mimeType: string; text?: string };
    headersSize: number;
    bodySize: number;
  };
  timings: {
    blocked: number;
    dns: number;
    connect: number;
    ssl: number;
    send: number;
    wait: number;
    receive: number;
  };
  resourceType?: string;
  serverIPAddress?: string;
}

export interface HARData {
  log: {
    version: string;
    creator: { name: string; version: string };
    pages: { startedDateTime: string; id: string; title: string }[];
    entries: HAREntry[];
  };
}

export interface Screenshot {
  id: string;
  timestamp: number;
  dataUrl: string;
  url: string;
  title: string;
}

export interface DOMSnapshot {
  id: string;
  timestamp: number;
  html: string;
  url: string;
  title: string;
}

export interface CaptureStatus {
  enabled: boolean;
  stats: {
    harEntries: number;
    screenshots: number;
    domSnapshots: number;
  };
}

// ═══════════════════════════════════════════════════════
// IOC Enrichment Types
// ═══════════════════════════════════════════════════════

export type IOCType = 'ip' | 'domain' | 'url' | 'hash';
export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error';
export type ProviderName = 'virustotal' | 'abuseipdb' | 'otx' | 'urlhaus' | 'whois';

export interface EnrichmentResult {
  provider: ProviderName;
  ioc: string;
  iocType: IOCType;
  verdict: Verdict;
  confidence: number;
  summary: string;
  details: Record<string, any>;
  timestamp: number;
  error?: string;
}

export interface IOCEntry {
  value: string;
  type: IOCType;
  source: string;
  firstSeen: number;
  results: EnrichmentResult[];
  status: 'pending' | 'enriching' | 'done' | 'error' | 'skipped';
  safe?: boolean;
  domain?: string;
}

export interface APIKeyConfig {
  virustotal?: string;
  abuseipdb?: string;
  otx?: string;
  urlhaus?: string;
}

// ═══════════════════════════════════════════════════════
// File Analysis Types
// ═══════════════════════════════════════════════════════

export type FileRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type FileAnalysisStatus = 'downloading' | 'hashing' | 'analyzing' | 'enriching' | 'submitting' | 'password-required' | 'extracting' | 'complete' | 'error';
export type SandboxProviderName = 'virustotal' | 'hybridanalysis' | 'joesandbox' | 'cuckoo';

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface AnalysisFinding {
  severity: FileRiskLevel;
  category: string;
  description: string;
  mitre?: string;
}

export interface StaticAnalysisResult {
  fileType: string;
  mimeType: string;
  entropy: number;
  findings: AnalysisFinding[];
  metadata: Record<string, any>;
  strings?: string[];
}

export interface SandboxResult {
  provider: SandboxProviderName;
  status: 'submitted' | 'queued' | 'analyzing' | 'complete' | 'error';
  submissionId?: string;
  reportUrl?: string;
  verdict?: string;
  score?: number;
  details: Record<string, any>;
  timestamp: number;
  error?: string;
}

export interface ArchiveInfo {
  isArchive: boolean;
  isEncrypted: boolean;
  archiveType: 'zip' | 'rar' | '7z' | 'pdf' | 'office' | 'unknown';
  entryCount?: number;
  passwordError?: string;
}

export interface QuarantinedFile {
  id: string;
  sessionId: string;
  originalName: string;
  url: string;
  fileSize: number;
  hashes: FileHashes | null;
  quarantinePath: string;
  status: FileAnalysisStatus;
  riskLevel: FileRiskLevel;
  staticAnalysis: StaticAnalysisResult | null;
  sandboxResults: SandboxResult[];
  hashEnrichmentDone: boolean;
  createdAt: number;
  error?: string;
  archiveInfo?: ArchiveInfo;
  childFileIds?: string[];
  parentArchiveId?: string;
  behavioralAnalysisDone?: boolean;
  behavioralAnalysisRunning?: boolean;
}

export interface SandboxAPIKeyConfig {
  virustotal?: string;
  hybridanalysis?: string;
  joesandbox?: string;
  cuckoo_url?: string;
  cuckoo?: string;
}

// ═══════════════════════════════════════════════════════
// Whitelist Types
// ═══════════════════════════════════════════════════════

export interface DomainWhitelist {
  domains: string[];
  patterns: string[];
  useBuiltIn: boolean;
}

// ═══════════════════════════════════════════════════════
// Report & Export Types
// ═══════════════════════════════════════════════════════

export type ReportFormat = 'html' | 'json' | 'zip' | 'pdf';

export interface ReportConfig {
  sessionId: string;
  format: ReportFormat;
  title: string;
  analystName: string;
  analystNotes: string;
  sections: {
    networkAnalysis: boolean;
    iocIntelligence: boolean;
    fileAnalysis: boolean;
    visualEvidence: boolean;
    timeline: boolean;
  };
  options: {
    includeScreenshots: boolean;
    includeDOMSnapshots: boolean;
    includeRawHAR: boolean;
  };
  timelineEvents: { time: string; event: string; detail: string; type: 'info' | 'warning' | 'danger' | 'success' }[];
}

export interface ReportPreview {
  sessionId: string;
  sessionCreatedAt: number;
  networkRequests: number;
  uniqueDomains: number;
  iocTotal: number;
  iocMalicious: number;
  iocSuspicious: number;
  filesAnalyzed: number;
  filesCritical: number;
  screenshots: number;
  domSnapshots: number;
}

export interface ReportProgress {
  stage: string;
  percent: number;
}

export interface ReportResult {
  success: boolean;
  filePath?: string;
  fileSize?: number;
  html?: string;
  error?: string;
}

// ═══════════════════════════════════════════════════════
// Email/Phishing Analysis Types
// ═══════════════════════════════════════════════════════

export interface ReceivedHop {
  from: string;
  by: string;
  timestamp: number;
  delay: number;
  ip: string;
}

export interface AuthenticationResult {
  method: 'spf' | 'dkim' | 'dmarc';
  result: 'pass' | 'fail' | 'softfail' | 'none' | 'neutral' | 'temperror' | 'permerror';
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
}

export type PhishingCategory = 'spoofing' | 'authentication' | 'content' | 'links' | 'attachments' | 'urgency' | 'brand';
export type PhishingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type PhishingVerdict = 'likely_phishing' | 'suspicious' | 'likely_legitimate';

export interface PhishingIndicator {
  id: string;
  category: PhishingCategory;
  severity: PhishingSeverity;
  description: string;
  evidence: string;
}

export interface PhishingScore {
  score: number;
  verdict: PhishingVerdict;
  indicators: PhishingIndicator[];
  breakdown: Record<PhishingCategory, number>;
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

// ═══════════════════════════════════════════════════════
// Content Analysis Types
// ═══════════════════════════════════════════════════════

export type ContentFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ContentFindingCategory =
  | 'eval_obfuscation'
  | 'hidden_content'
  | 'credential_harvest'
  | 'crypto_mining'
  | 'base64_payload'
  | 'suspicious_redirect'
  | 'external_script'
  | 'data_exfil';

export interface ContentFinding {
  id: string;
  sessionId: string;
  url: string;
  requestId: string;
  timestamp: number;
  category: ContentFindingCategory;
  severity: ContentFindingSeverity;
  description: string;
  evidence: string;
  mimeType: string;
}

// ═══════════════════════════════════════════════════════
// YARA Rules Engine Types
// ═══════════════════════════════════════════════════════

export interface YARAStringDef {
  id: string;
  type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers: { nocase?: boolean; wide?: boolean; ascii?: boolean; fullword?: boolean };
}

export interface YARARule {
  id: string;
  name: string;
  tags: string[];
  metadata: Record<string, string | number | boolean>;
  strings: YARAStringDef[];
  condition: string;
  enabled: boolean;
  source: 'custom' | 'builtin';
  pack?: string;
}

export interface YARAMatchedString {
  stringId: string;
  offset: number;
  length: number;
  data: string;
}

export interface YARAMatch {
  ruleId: string;
  ruleName: string;
  tags: string[];
  metadata: Record<string, string | number | boolean>;
  matchedStrings: YARAMatchedString[];
}

export interface YARAScanResult {
  targetId: string;
  targetName: string;
  targetType: 'file' | 'content';
  matches: YARAMatch[];
  rulesScanned: number;
  scanTimeMs: number;
  timestamp: number;
}

export interface YARARulePack {
  id: string;
  name: string;
  description: string;
  ruleCount: number;
  enabled: boolean;
}

// ═══════════════════════════════════════════════════════
// Threat Intelligence Feed Types
// ═══════════════════════════════════════════════════════

export type ThreatFeedAuthType = 'none' | 'basic' | 'apikey';
export type ThreatFeedSyncStatus = 'idle' | 'syncing' | 'synced' | 'error';
export type ThreatIOCType = 'ip' | 'domain' | 'url' | 'hash';
export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ThreatFeedConfig {
  id: string;
  name: string;
  serverUrl: string;
  apiRootPath: string;
  collectionId: string;
  authType: ThreatFeedAuthType;
  username?: string;
  password?: string;
  apiKey?: string;
  enabled: boolean;
  pollIntervalMs: number;
  lastSyncTimestamp: number;
  lastSyncStatus: ThreatFeedSyncStatus;
  indicatorCount: number;
  lastError?: string;
}

export interface TAXIIServerInfo {
  title: string;
  description?: string;
  apiRoots: string[];
}

export interface TAXIICollection {
  id: string;
  title: string;
  description?: string;
  canRead: boolean;
  canWrite: boolean;
}

export interface ThreatIOC {
  value: string;
  type: ThreatIOCType;
  feedId: string;
  feedName: string;
  stixId?: string;
  labels: string[];
  severity: ThreatSeverity;
  description?: string;
  mitre?: string;
  addedAt: number;
}

export interface ThreatFeedMatch {
  sessionId: string;
  ioc: ThreatIOC;
  matchedValue: string;
  matchSource: 'serverIP' | 'hostname' | 'url';
  harEntryUrl: string;
  timestamp: number;
}

export interface BulkImportResult {
  imported: number;
  duplicates: number;
  errors: number;
  feedId: string;
  feedName: string;
}

export interface FeedMatcherStats {
  totalIOCs: number;
  feedBreakdown: Record<string, number>;
}

// ═══════════════════════════════════════════════════════
// Auth Types
// ═══════════════════════════════════════════════════════

export type AuthState = 'checking' | 'authenticated' | 'unauthenticated';

export interface AuthUser {
  id: string;
  email: string;
  analystName: string;
  chatSessionId?: string;
  avatar?: string;
  emailVerified?: boolean;
}

export interface LoginResult {
  success: boolean;
  user?: AuthUser;
  error?: string;
}

export interface RegisterResult {
  success: boolean;
  message?: string;
  error?: string;
}

// ═══════════════════════════════════════════════════════
// Session Chat Types
// ═══════════════════════════════════════════════════════

export type PresenceStatus = 'online' | 'busy' | 'offline';
export type ChatConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

export interface ChatContact {
  sessionId: string;
  displayName: string;
  addedAt: number;
  lastMessageAt?: number;
  unreadCount: number;
  presence: PresenceStatus;
  lastSeen?: number;
  approved?: boolean;
}

export interface ContactLookupResult {
  analystName: string;
  sessionIdHash: string;
}

export interface ChatMessage {
  id: string;
  conversationId: string;
  senderSessionId: string;
  recipientSessionId: string;
  body: string;
  timestamp: number;
  status: 'sending' | 'sent' | 'failed';
  read: boolean;
}

export interface ChatConversation {
  id: string;
  contactSessionId: string;
  displayName: string;
  lastMessage?: ChatMessage;
  unreadCount: number;
  presence: PresenceStatus;
  lastSeen?: number;
}

// ═══════════════════════════════════════════════════════
// Auto-Update Types
// ═══════════════════════════════════════════════════════

export type UpdateStatus =
  | 'idle'
  | 'checking'
  | 'available'
  | 'not-available'
  | 'downloading'
  | 'downloaded'
  | 'error';

export interface UpdateState {
  status: UpdateStatus;
  currentVersion: string;
  availableVersion: string | null;
  downloadProgress: number;
  error: string | null;
}

// ═══════════════════════════════════════════════════════
// API Interface
// ═══════════════════════════════════════════════════════

export interface ShieldTierAPI {
  auth: {
    login: (email: string, password: string) => Promise<LoginResult>;
    register: (email: string, password: string, analystName: string) => Promise<RegisterResult>;
    logout: () => Promise<{ success: boolean }>;
    getUser: () => Promise<AuthUser | null>;
    restoreSession: () => Promise<LoginResult>;
    changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
    resendVerification: () => Promise<{ success: boolean; message?: string; error?: string }>;
    refreshProfile: () => Promise<LoginResult>;
    updateProfile: (updates: { analystName?: string; avatar?: string }) => Promise<LoginResult>;
    syncCases: (cases: any[]) => Promise<{ success: boolean; error?: string }>;
    getCases: () => Promise<{ success: boolean; cases?: any[]; error?: string }>;
    setSyncKey: (syncKey: string) => Promise<{ success: boolean; syncToken?: string; error?: string }>;
    onSessionExpired: (callback: () => void) => () => void;
  };
  session: {
    create: (config?: { url?: string; caseName?: string }) => Promise<InvestigationSession>;
    destroy: (sessionId: string) => Promise<{ success: boolean }>;
    list: () => Promise<InvestigationSession[]>;
  };
  proxy: {
    configure: (config: ProxyConfig) => Promise<{ success: boolean; message: string }>;
    getConfig: () => Promise<ProxyConfig | null>;
    test: (config: ProxyConfig) => Promise<{ success: boolean; ip?: string; error?: string }>;
  };
  view: {
    create: (sessionId: string) => Promise<{ success: boolean; error?: string }>;
    navigate: (sessionId: string, url: string) => Promise<{ success: boolean; error?: string }>;
    goBack: (sessionId: string) => Promise<boolean>;
    goForward: (sessionId: string) => Promise<boolean>;
    reload: (sessionId: string) => Promise<boolean>;
    stop: (sessionId: string) => Promise<boolean>;
    setBounds: (sessionId: string, bounds: { x: number; y: number; width: number; height: number }) => Promise<boolean>;
    hide: (sessionId: string) => Promise<boolean>;
    getNavState: (sessionId: string) => Promise<NavigationState | null>;
    setZoom: (sessionId: string, factor: number) => Promise<boolean>;
    getZoom: (sessionId: string) => Promise<number>;
    analyzeNow: (sessionId: string) => Promise<SandboxResult | null>;
    onNavStateChanged: (callback: (sessionId: string, state: NavigationState) => void) => () => void;
    onLoadError: (callback: (sessionId: string, error: LoadError) => void) => () => void;
    onSandboxResult: (callback: (sessionId: string, result: SandboxResult) => void) => () => void;
  };
  capture: {
    enable: (sessionId: string) => Promise<{ success: boolean; error?: string }>;
    disable: (sessionId: string) => Promise<{ success: boolean }>;
    getHAR: (sessionId: string) => Promise<HARData | null>;
    takeScreenshot: (sessionId: string) => Promise<Screenshot | null>;
    takeDOMSnapshot: (sessionId: string) => Promise<DOMSnapshot | null>;
    getStatus: (sessionId: string) => Promise<CaptureStatus>;
    getScreenshots: (sessionId: string) => Promise<Screenshot[]>;
    getDOMSnapshots: (sessionId: string) => Promise<DOMSnapshot[]>;
    onNetworkEvent: (callback: (sessionId: string, entry: HAREntry) => void) => () => void;
  };
  enrichment: {
    query: (sessionId: string, ioc: string) => Promise<IOCEntry | null>;
    getResults: (sessionId: string) => Promise<IOCEntry[]>;
    getSummary: (sessionId: string) => Promise<{
      total: number;
      malicious: number;
      suspicious: number;
      clean: number;
      pending: number;
      error: number;
      byType: Record<IOCType, number>;
    }>;
    setAPIKeys: (keys: APIKeyConfig) => Promise<{ success: boolean }>;
    getAPIKeys: () => Promise<Record<string, string>>;
    onResult: (callback: (sessionId: string, entry: IOCEntry) => void) => () => void;
  };
  fileanalysis: {
    getFiles: (sessionId: string) => Promise<QuarantinedFile[]>;
    getFile: (sessionId: string, fileId: string) => Promise<QuarantinedFile | null>;
    resubmit: (sessionId: string, fileId: string) => Promise<boolean>;
    analyzeBehavior: (sessionId: string, fileId: string) => Promise<boolean>;
    deleteFile: (sessionId: string, fileId: string) => Promise<boolean>;
    setSandboxKeys: (keys: SandboxAPIKeyConfig) => Promise<{ success: boolean }>;
    getSandboxKeys: () => Promise<Record<string, string>>;
    submitArchivePassword: (sessionId: string, fileId: string, password: string) => Promise<{ success: boolean }>;
    skipArchivePassword: (sessionId: string, fileId: string) => Promise<{ success: boolean }>;
    uploadFiles: (sessionId: string) => Promise<{ fileCount: number } | null>;
    onFileUpdate: (callback: (sessionId: string, file: QuarantinedFile) => void) => () => void;
  };
  config: {
    get: (key: string) => Promise<any>;
    set: (key: string, value: any) => Promise<{ success: boolean }>;
    getWhitelist: () => Promise<DomainWhitelist>;
    setWhitelist: (whitelist: DomainWhitelist) => Promise<{ success: boolean }>;
    getProxyConfig: () => Promise<ProxyConfig | undefined>;
    isDomainWhitelisted: (domain: string) => Promise<boolean>;
    getAnalystProfile: () => Promise<{ name: string; createdAt: number } | null>;
    setAnalystProfile: (name: string) => Promise<{ success: boolean; error?: string }>;
    peekNextCaseId: () => Promise<string>;
  };
  report: {
    generate: (config: ReportConfig) => Promise<ReportResult>;
    preview: (sessionId: string) => Promise<ReportPreview>;
    onProgress: (callback: (progress: ReportProgress) => void) => () => void;
  };
  email: {
    parseRaw: (sessionId: string, rawSource: string) => Promise<ParsedEmail>;
    getEmails: (sessionId: string) => Promise<ParsedEmail[]>;
    getEmail: (sessionId: string, emailId: string) => Promise<ParsedEmail | null>;
    openFile: (sessionId: string) => Promise<ParsedEmail | null>;
    onEmailParsed: (callback: (sessionId: string, email: ParsedEmail) => void) => () => void;
  };
  contentanalysis: {
    getFindings: (sessionId: string) => Promise<ContentFinding[]>;
    onFinding: (callback: (sessionId: string, finding: ContentFinding) => void) => () => void;
  };
  yara: {
    getRules: () => Promise<YARARule[]>;
    getRule: (ruleId: string) => Promise<YARARule | null>;
    addRule: (rule: Omit<YARARule, 'id' | 'source'>) => Promise<YARARule>;
    updateRule: (ruleId: string, updates: Partial<YARARule>) => Promise<YARARule | null>;
    deleteRule: (ruleId: string) => Promise<boolean>;
    importRules: (yarText: string) => Promise<YARARule[]>;
    exportRules: (ruleIds: string[]) => Promise<string>;
    getBuiltinPacks: () => Promise<YARARulePack[]>;
    togglePack: (packId: string, enabled: boolean) => Promise<{ success: boolean }>;
    scanFile: (sessionId: string, fileId: string, filePath: string, fileName: string) => Promise<YARAScanResult>;
    scanContent: (sessionId: string, content: string, name: string) => Promise<YARAScanResult>;
    getScanResults: (sessionId: string) => Promise<YARAScanResult[]>;
    onScanResult: (callback: (sessionId: string, result: YARAScanResult) => void) => () => void;
  };
  threatfeed: {
    listFeeds: () => Promise<ThreatFeedConfig[]>;
    addFeed: (config: Partial<ThreatFeedConfig>) => Promise<ThreatFeedConfig>;
    updateFeed: (feedId: string, updates: Partial<ThreatFeedConfig>) => Promise<ThreatFeedConfig | null>;
    deleteFeed: (feedId: string) => Promise<boolean>;
    toggleFeed: (feedId: string, enabled: boolean) => Promise<{ success: boolean }>;
    discover: (serverUrl: string, auth: { type: ThreatFeedAuthType; username?: string; password?: string; apiKey?: string }) => Promise<TAXIIServerInfo>;
    getCollections: (feedId: string) => Promise<TAXIICollection[]>;
    syncFeed: (feedId: string) => Promise<{ success: boolean }>;
    syncAll: () => Promise<{ success: boolean }>;
    getMatches: (sessionId: string) => Promise<ThreatFeedMatch[]>;
    importCSV: (csvText: string, feedName: string) => Promise<BulkImportResult>;
    importSTIX: (jsonText: string, feedName: string) => Promise<BulkImportResult>;
    getStats: () => Promise<FeedMatcherStats>;
    onMatch: (callback: (match: ThreatFeedMatch) => void) => () => void;
    onSyncStatus: (callback: (status: { feedId: string; status: ThreatFeedSyncStatus; indicatorCount: number; lastSyncTimestamp: number; error?: string }) => void) => () => void;
  };
  chat: {
    getIdentity: () => Promise<{ sessionId: string; mnemonic: string } | null>;
    getContacts: () => Promise<ChatContact[]>;
    addContact: (sessionId: string, displayName: string) => Promise<ChatContact>;
    removeContact: (sessionId: string) => Promise<boolean>;
    updateContactName: (sessionId: string, name: string) => Promise<ChatContact | null>;
    getConversations: () => Promise<ChatConversation[]>;
    getMessages: (conversationId: string, limit?: number, before?: number) => Promise<ChatMessage[]>;
    sendMessage: (recipientSessionId: string, body: string) => Promise<ChatMessage>;
    markAsRead: (conversationId: string) => Promise<void>;
    getConnectionStatus: () => Promise<ChatConnectionStatus>;
    setPresence: (status: PresenceStatus) => Promise<void>;
    acknowledgeOnboarding: () => Promise<void>;
    getMessageRequests: () => Promise<ChatContact[]>;
    approveContact: (sessionId: string) => Promise<ChatContact | null>;
    rejectContact: (sessionId: string) => Promise<boolean>;
    lookupUser: (sessionId: string) => Promise<ContactLookupResult | null>;
    onMessageReceived: (callback: (message: ChatMessage) => void) => () => void;
    onMessageSent: (callback: (message: ChatMessage) => void) => () => void;
    onMessageFailed: (callback: (data: { messageId: string; error: string }) => void) => () => void;
    onIdentityCreated: (callback: (data: { sessionId: string; mnemonic: string }) => void) => () => void;
    onConnectionStatus: (callback: (status: ChatConnectionStatus) => void) => () => void;
    onPresenceUpdate: (callback: (data: { sessionId: string; status: PresenceStatus; lastSeen: number }) => void) => () => void;
    onMessageRequest: (callback: (data: ChatContact) => void) => () => void;
  };
  vm: {
    getQEMUStatus: () => Promise<any>;
    installQEMU: () => Promise<any>;
    listImages: () => Promise<any[]>;
    downloadImage: (imageId: string) => Promise<any>;
    spawnVM: (sessionId: string, fileId: string, config: any) => Promise<string | null>;
    killVM: (instanceId: string) => Promise<any>;
    getInstances: (sessionId: string) => Promise<any[]>;
    getResult: (sessionId: string, instanceId: string) => Promise<any>;
    hasSnapshot: (imageId: string) => Promise<boolean>;
    prepareSnapshot: (imageId: string) => Promise<any>;
    getCACertPEM: () => Promise<string | null>;
    buildAgent: (os?: string) => Promise<any>;
    getAgentStatus: (os?: string) => Promise<any>;
    onStatus: (callback: (update: any) => void) => () => void;
    onInstallProgress: (callback: (message: string) => void) => () => void;
    onImageDownloadProgress: (callback: (progress: any) => void) => () => void;
    onSnapshotProgress: (callback: (data: { imageId: string; message: string }) => void) => () => void;
    onScreenshot: (callback: (data: { instanceId: string; sessionId: string; screenshot: { timestamp: number; data: string } }) => void) => () => void;
  };
  clipboard: {
    writeText: (text: string) => Promise<void>;
    readText: () => Promise<string>;
  };
  update: {
    check: () => Promise<UpdateState>;
    download: () => Promise<void>;
    install: () => Promise<void>;
    getState: () => Promise<UpdateState>;
    onStatus: (callback: (state: UpdateState) => void) => () => void;
  };
  platform: string;
}

declare global {
  interface Window {
    shieldtier: ShieldTierAPI;
  }
}
