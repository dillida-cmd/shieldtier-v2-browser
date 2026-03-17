// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Shared Utilities, Constants & Helpers
// ---------------------------------------------------------------------------

// ═══════════════════════════════════════════════════════════════════════════
// Color / Style Helpers
// ═══════════════════════════════════════════════════════════════════════════

export function getScoreColor(score: number): string {
  if (score >= 70) return 'text-red-400';
  if (score >= 40) return 'text-orange-400';
  return 'text-green-400';
}

export function getScoreBg(score: number): string {
  if (score >= 70) return 'bg-red-600/20 border-red-500/30';
  if (score >= 40) return 'bg-orange-600/20 border-orange-500/30';
  return 'bg-green-600/20 border-green-500/30';
}

export function getVerdictLabel(verdict: string): string {
  switch (verdict) {
    case 'likely_phishing': return 'Likely Phishing';
    case 'suspicious': return 'Suspicious';
    case 'likely_legitimate': return 'Likely Legitimate';
    default: return verdict;
  }
}

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-600/20 text-red-400';
    case 'high': return 'bg-orange-600/20 text-orange-400';
    case 'medium': return 'bg-yellow-600/20 text-yellow-400';
    case 'low': return 'bg-blue-600/20 text-blue-400';
    default: return 'bg-gray-600/20 text-gray-400';
  }
}

export function getAuthBadge(result: string): string {
  switch (result) {
    case 'pass': return 'bg-green-600/20 text-green-400 border-green-500/30';
    case 'fail': return 'bg-red-600/20 text-red-400 border-red-500/30';
    case 'softfail': return 'bg-orange-600/20 text-orange-400 border-orange-500/30';
    default: return 'bg-gray-600/20 text-gray-400 border-gray-500/30';
  }
}

export function getRiskColor(level: string) {
  switch (level) {
    case 'critical': return { bg: 'bg-red-600/20', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500' };
    case 'high': return { bg: 'bg-orange-600/20', text: 'text-orange-400', border: 'border-orange-500/30', dot: 'bg-orange-500' };
    case 'medium': return { bg: 'bg-yellow-600/20', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' };
    case 'low': return { bg: 'bg-blue-600/20', text: 'text-blue-400', border: 'border-blue-500/30', dot: 'bg-blue-500' };
    default: return { bg: 'bg-gray-600/20', text: 'text-gray-400', border: 'border-gray-500/30', dot: 'bg-gray-500' };
  }
}

export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

// ═══════════════════════════════════════════════════════════════════════════
// HTML to Text conversion
// ═══════════════════════════════════════════════════════════════════════════

/** Strip HTML tags and decode entities to produce readable plain text. */
export function htmlToText(html: string): string {
  // Remove style/script blocks entirely
  let text = html.replace(/<style[\s\S]*?<\/style>/gi, '');
  text = text.replace(/<script[\s\S]*?<\/script>/gi, '');
  // Replace block-level tags with newlines
  text = text.replace(/<\/(p|div|tr|li|h[1-6]|br\s*\/?)>/gi, '\n');
  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/(td|th)>/gi, '\t');
  // Strip remaining tags
  text = text.replace(/<[^>]+>/g, '');
  // Decode common HTML entities
  text = text.replace(/&nbsp;/gi, ' ');
  text = text.replace(/&amp;/gi, '&');
  text = text.replace(/&lt;/gi, '<');
  text = text.replace(/&gt;/gi, '>');
  text = text.replace(/&quot;/gi, '"');
  text = text.replace(/&#39;/gi, "'");
  text = text.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)));
  // Collapse multiple blank lines
  text = text.replace(/\n{3,}/g, '\n\n');
  return text.trim();
}

// ═══════════════════════════════════════════════════════════════════════════
// Header Analysis Constants & Helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Header groups for organized display. */
export const HEADER_GROUPS: { label: string; keys: string[]; color: string }[] = [
  {
    label: 'Envelope',
    keys: ['from', 'to', 'cc', 'bcc', 'reply-to', 'return-path', 'sender', 'subject', 'date', 'message-id', 'in-reply-to', 'references'],
    color: 'border-blue-500/40',
  },
  {
    label: 'Authentication',
    keys: ['authentication-results', 'received-spf', 'dkim-signature', 'arc-seal', 'arc-message-signature', 'arc-authentication-results'],
    color: 'border-purple-500/40',
  },
  {
    label: 'Content',
    keys: ['content-type', 'content-transfer-encoding', 'content-disposition', 'content-language', 'mime-version'],
    color: 'border-green-500/40',
  },
  {
    label: 'Security',
    keys: ['x-sender-ip', 'x-originating-ip', 'x-ms-exchange-organization-scl', 'x-forefront-antispam-report', 'x-microsoft-antispam', 'x-ms-exchange-organization-authsource', 'x-ms-exchange-organization-authas', 'x-spam-status', 'x-spam-score', 'x-virus-scanned'],
    color: 'border-red-500/40',
  },
];

/** Header explanations — helps L1 SOC analysts understand what each header means. */
export const HEADER_HINTS: Record<string, string> = {
  // Envelope
  'from': 'The sender address displayed to the recipient. Can be spoofed — always verify with authentication results.',
  'to': 'The intended recipient(s) of the email.',
  'cc': 'Carbon copy recipients — visible to all recipients.',
  'bcc': 'Blind carbon copy — recipients hidden from others. Unusual to see in received mail.',
  'reply-to': 'Where replies go. If different from "From", could indicate spoofing or phishing.',
  'return-path': 'Bounce address — where delivery failures are sent. Should match sender domain.',
  'sender': 'The actual sender when different from "From" (e.g., mailing lists). Mismatch may indicate spoofing.',
  'subject': 'Email subject line. Check for urgency language, brand impersonation, or suspicious patterns.',
  'date': 'When the email was composed. Large discrepancy with received time may indicate queuing or manipulation.',
  'message-id': 'Unique identifier for this email. Legitimate emails have domain matching the sender.',
  'in-reply-to': 'Message-ID of the email this replies to. Helps verify conversation threading.',
  'references': 'Chain of Message-IDs in the conversation thread.',
  'mime-version': 'MIME protocol version (usually 1.0). Standard header, not security-relevant.',
  // Authentication
  'authentication-results': 'Combined SPF, DKIM, and DMARC results from the receiving mail server. Key for verifying sender legitimacy.',
  'received-spf': 'SPF check result — verifies the sending IP is authorized by the sender domain. "pass" = legitimate, "fail" = spoofed.',
  'dkim-signature': 'Cryptographic signature proving the email was sent by the claimed domain and was not modified in transit.',
  'arc-seal': 'Authenticated Received Chain seal — preserves authentication across forwarding. Helps verify forwarded mail.',
  'arc-message-signature': 'ARC signature covering message headers — maintains trust through mail forwarding chains.',
  'arc-authentication-results': 'Authentication results captured at each forwarding hop. Useful for tracing forwarded email trust.',
  // Content
  'content-type': 'The format of the email body (text/plain, text/html, multipart). Check for unusual MIME types.',
  'content-transfer-encoding': 'How the body is encoded (base64, quoted-printable, 7bit). Standard encoding, not usually suspicious.',
  'content-disposition': 'Whether content is inline or an attachment. Check attachment filenames for suspicious extensions.',
  'content-language': 'Language of the email content. Mismatch with sender region may indicate phishing.',
  // Microsoft / Exchange Organization
  'x-ms-exchange-organization-scl': 'Spam Confidence Level (0-9). 0-1 = not spam, 5+ = likely spam, 9 = definite spam.',
  'x-ms-exchange-organization-authsource': 'Exchange server that authenticated the sender. Internal emails show your org server.',
  'x-ms-exchange-organization-authas': 'How the sender was authenticated: "Internal" = from your org, "Anonymous" = external.',
  'x-ms-exchange-organization-network-message-id': 'Unique message tracking ID in Exchange. Use for log correlation in compliance search.',
  'x-ms-exchange-organization-originalclientipaddress': 'Original client IP before proxying. Key forensic indicator for sender location.',
  'x-ms-exchange-organization-originalserveripaddress': 'Original server IP in Exchange routing.',
  'x-ms-exchange-organization-recordreviewcfmtype': 'Compliance/review classification type set by Exchange.',
  'x-ms-exchange-organization-expirationstarttime': 'When the message expiration timer starts. Used for message lifecycle policies.',
  'x-ms-exchange-organization-expirationstarttimerreason': 'Reason the expiration timer was set (e.g., policy, user-defined).',
  'x-ms-exchange-organization-expirationinterval': 'How long before the message expires. Format: days:hours:minutes:seconds.',
  'x-ms-exchange-organization-expirationintervalreason': 'Reason for the expiration interval (e.g., org policy, transport rule).',
  'x-ms-exchange-organization-messagedirectionality': 'Message direction: "Incoming" = received from external, "Originating" = sent from your org.',
  'x-ms-exchange-organization-pcl': 'Phishing Confidence Level (0-8). Higher = more likely phishing. 3+ usually triggers warnings.',
  'x-ms-exchange-organization-submissionquotaskipped': 'Whether submission quota checks were skipped for this message.',
  // Microsoft Exchange Cross-Tenant
  'x-ms-exchange-crosstenant-authas': 'Cross-tenant auth type. "Anonymous" = external sender (expected for inbound).',
  'x-ms-exchange-crosstenant-authsource': 'Server that performed authentication in cross-tenant routing.',
  'x-ms-exchange-crosstenant-originalarrivaltime': 'When the email first arrived at Exchange infrastructure (UTC).',
  'x-ms-exchange-crosstenant-fromentityheader': 'Source: "Hosted" = O365 tenant, "Internet" = external, "HybridOnPrem" = on-premises Exchange.',
  'x-ms-exchange-crosstenant-id': 'Azure AD tenant ID of the sending organization. Verify against known tenant IDs.',
  'x-ms-exchange-crosstenant-network-message-id': 'Cross-tenant message tracking ID. Correlate across tenant boundaries.',
  'x-ms-exchange-crosstenant-rms-persistedconsumerorg': 'Rights Management Service consumer org GUID. Related to encryption/DRM.',
  // Microsoft Exchange Transport
  'x-ms-exchange-transport-crosstenantheadersstamped': 'Exchange server that stamped cross-tenant headers. Shows processing path.',
  'x-ms-exchange-transport-endtoendlatency': 'Total delivery time from send to receipt. High latency may indicate queueing.',
  'x-ms-exchange-processed-by-bccfoldering': 'Internal Exchange routing stamp for BCC processing. Server IP shown.',
  'x-ms-exchange-eopdirect': 'Whether email went directly through Exchange Online Protection. "true" = direct EOP path.',
  'x-ms-exchange-messageSentRepresentingType': 'Whether sent directly or on behalf of someone (delegation).',
  'x-ms-tnef-correlator': 'Transport Neutral Encapsulation Format ID. Relates to rich formatting, usually benign.',
  'x-ms-has-attach': 'Whether Exchange detected attachments. "yes" = attachments present.',
  // Microsoft Anti-Spam
  'x-microsoft-antispam': 'Microsoft spam filter verdict. Contains BCL (Bulk Complaint Level) and other signals.',
  'x-microsoft-antispam-message-info': 'Encrypted Microsoft EOP telemetry. Not human-readable — only Microsoft servers can decode this. Contains internal spam scoring signals, routing data, and ML model outputs. The actual verdict is in x-forefront-antispam-report and x-microsoft-antispam headers instead.',
  'x-microsoft-antispam-mailbox-delivery': 'Mailbox delivery verdict. Shows final delivery decision (junk folder, inbox, blocked).',
  'x-forefront-antispam-report': 'Forefront spam report. Key: SFV=filter verdict, SCL=spam confidence, CIP=connecting IP, CAT=category.',
  'x-ms-exchange-antispam-relay': 'Anti-spam relay info. Shows which anti-spam engine processed the email.',
  'x-ms-exchange-antispam-messagedata': 'Extended anti-spam analysis data (may span multiple headers).',
  // Microsoft Office 365
  'x-ms-office365-filtering-correlation-id': 'O365 filtering correlation ID. Use to track this email through Microsoft security logs.',
  'x-ms-traffictypediagnostic': 'Exchange traffic type diagnostic. Shows server + routing type (e.g., EE_ = Exchange Edge).',
  'x-ms-publictraffictype': 'Traffic classification: "Email" = standard email, "Calendar" = calendar invite.',
  'x-ms-userlastlogontime': 'When the recipient last logged in. Stale accounts may be targeted in phishing.',
  // EOP (Exchange Online Protection)
  'x-eopattributedmessage': 'EOP attribution flag. 0 = message not attributed to a specific policy.',
  'x-eoptentantattributedmessage': 'EOP tenant attribution. Contains tenant GUID and flags.',
  // Sender ID / SPF (legacy)
  'x-sid-pra': 'Sender ID Purported Responsible Address — the address SID validates against.',
  'x-sid-result': 'Sender ID check result: PASS, FAIL, NONE. Legacy auth — SPF/DKIM/DMARC supersede this.',
  // DKIM
  'x-dkim': 'DKIM verification result from the receiving server. "pass" = signature valid.',
  // Incoming Header Tracking
  'x-incomingtopheadermarker': 'Exchange top header marker with checksums. Used for message integrity verification.',
  'x-incomingheadercount': 'Number of headers in the email. Unusually high counts may indicate header injection.',
  // Sender IP / Origin
  'x-sender-ip': 'IP address of the sending mail server. Look up for geolocation and reputation.',
  'x-originating-ip': 'Original IP where email was composed (sender device IP). Key forensic indicator.',
  'x-mailer': 'Email client/software used to send. Unusual clients may indicate automated phishing tools.',
  'x-mimeole': 'MIME OLE version — indicates older Outlook/Windows Mail. May suggest legacy or spoofed client.',
  // Spam / Virus
  'x-spam-status': 'SpamAssassin verdict: "Yes" or "No" with score. Higher score = more likely spam.',
  'x-spam-score': 'Numeric spam score. Typically 5+ is spam. Check against your org threshold.',
  'x-spam-flag': 'Simple spam flag: YES or NO.',
  'x-spam-checker-version': 'Version of spam checking software. Useful for verifying mail path.',
  'x-virus-scanned': 'Which antivirus engine scanned the email and result.',
  'x-virus-status': 'Antivirus scan result: "Clean" or infected.',
  // Google / Gmail
  'x-google-dkim-signature': 'Google\'s own DKIM signature. Verifies email passed through Google servers.',
  'x-gm-message-state': 'Internal Gmail message state tracking. Not security-relevant.',
  'x-google-smtp-source': 'Identifies the Google SMTP server that handled the email.',
  'x-received': 'Internal Google/mail server routing header. Shows path within infrastructure.',
  // Proofpoint / Security Gateways
  'x-proofpoint-virus-version': 'Proofpoint antivirus engine version used for scanning.',
  'x-proofpoint-spam-details': 'Proofpoint spam analysis breakdown.',
  'x-ironport-anti-spam-filtered': 'Cisco IronPort anti-spam indicator. "true" = scanned by IronPort.',
  'x-ironport-anti-spam-result': 'Cisco IronPort spam verdict and scoring details.',
  'x-barracuda-spam-score': 'Barracuda spam score. Check against threshold.',
  'x-barracuda-spam-status': 'Barracuda spam verdict.',
  // Mailing / Marketing
  'x-campaign-id': 'Marketing campaign ID. Suggests bulk/marketing email.',
  'x-report-abuse': 'Abuse reporting link. Legitimate senders include this.',
  'list-unsubscribe': 'Unsubscribe mechanism. Legitimate marketing includes this; phishing usually doesn\'t.',
  'x-sg-eid': 'SendGrid tracking ID. Email sent through SendGrid platform.',
  'x-sg-id': 'SendGrid internal message ID.',
  // Priority / Misc
  'x-priority': 'Email priority: 1=High, 3=Normal, 5=Low. Phishing often uses high priority for urgency.',
  'x-msmail-priority': 'Microsoft mail priority. Same as X-Priority.',
  'importance': 'Email importance: High, Normal, Low.',
  'x-auto-response-suppress': 'Controls auto-reply suppression. "All" suppresses out-of-office replies.',
  'x-originatororg': 'Originating organization (set by Exchange). Verify against expected sender org.',
  'thread-topic': 'Conversation topic for threading. Usually matches subject without Re:/Fw: prefix.',
  'thread-index': 'Binary thread index for Outlook conversation tracking.',
};

/** Pattern-based fallback hints for headers not in the exact-match dictionary. */
export const HEADER_HINT_PATTERNS: { pattern: RegExp; hint: string }[] = [
  { pattern: /^x-ms-exchange-organization-/i, hint: 'Microsoft Exchange organization header — internal Exchange routing/policy metadata.' },
  { pattern: /^x-ms-exchange-crosstenant-/i, hint: 'Microsoft cross-tenant routing header — tracks email between O365 tenants.' },
  { pattern: /^x-ms-exchange-transport-/i, hint: 'Microsoft Exchange transport header — delivery pipeline metadata.' },
  { pattern: /^x-ms-exchange-antispam/i, hint: 'Microsoft Exchange anti-spam header — spam analysis data.' },
  { pattern: /^x-ms-exchange/i, hint: 'Microsoft Exchange header — internal Exchange infrastructure metadata.' },
  { pattern: /^x-microsoft-antispam/i, hint: 'Microsoft anti-spam header — spam/phishing filter analysis data.' },
  { pattern: /^x-ms-office365/i, hint: 'Microsoft Office 365 header — O365 filtering and processing metadata.' },
  { pattern: /^x-ms-/i, hint: 'Microsoft header — internal Microsoft service metadata.' },
  { pattern: /^x-google-/i, hint: 'Google/Gmail internal header — Google mail infrastructure metadata.' },
  { pattern: /^x-proofpoint-/i, hint: 'Proofpoint security gateway header — email security scanning results.' },
  { pattern: /^x-ironport-/i, hint: 'Cisco IronPort header — email security appliance scanning results.' },
  { pattern: /^x-barracuda-/i, hint: 'Barracuda security gateway header — spam/virus scanning results.' },
  { pattern: /^x-spam-/i, hint: 'Spam filter header — anti-spam scoring and verdict.' },
  { pattern: /^x-virus-/i, hint: 'Antivirus header — virus scanning results.' },
  { pattern: /^x-eop/i, hint: 'Exchange Online Protection header — EOP filtering metadata.' },
  { pattern: /^x-sid-/i, hint: 'Sender ID header — legacy sender authentication (superseded by SPF/DKIM/DMARC).' },
  { pattern: /^x-sg-/i, hint: 'SendGrid header — email delivery platform tracking.' },
  { pattern: /^x-dkim/i, hint: 'DKIM verification result — cryptographic sender authentication check.' },
];

/** Look up a header hint: exact match first, then pattern-based fallback. */
export function getHeaderHint(key: string): string | null {
  const lower = key.toLowerCase();
  if (HEADER_HINTS[lower]) return HEADER_HINTS[lower];
  for (const { pattern, hint } of HEADER_HINT_PATTERNS) {
    if (pattern.test(lower)) return hint;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// Header Value Decoding & Smart Formatting
// ═══════════════════════════════════════════════════════════════════════════

/** Decode RFC 2047 encoded-word: =?charset?B?base64?= and =?charset?Q?qp?= */
export function decodeRFC2047(value: string): string {
  return value.replace(/=\?([^?]+)\?(B|Q)\?([^?]*)\?=/gi, (_match, _charset, encoding, encoded) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return atob(encoded);
      } else {
        return encoded
          .replace(/_/g, ' ')
          .replace(/=([0-9A-Fa-f]{2})/g, (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
      }
    } catch {
      return encoded;
    }
  });
}

/** Known x-forefront-antispam-report field explanations. */
export const ANTISPAM_FIELDS: Record<string, string> = {
  'CIP': 'Connecting IP address of the sending server',
  'CTRY': 'Country of the connecting IP',
  'LANG': 'Language of the email content',
  'SCL': 'Spam Confidence Level (0-1=not spam, 5+=likely spam, 9=high confidence spam)',
  'SRV': 'Service that processed the message',
  'IPV': 'IP validation result (CAL=from allow list, NLI=not listed)',
  'SFV': 'Spam Filter Verdict (SPM=spam, NSPM=not spam, SKN=skip/allow, BLK=blocked)',
  'H': 'HELO/EHLO hostname of the sending server',
  'PTR': 'Reverse DNS of the connecting IP',
  'CAT': 'Category of message (SPM=spam, PHSH=phishing, MALW=malware, HSPM=high confidence spam)',
  'SFTY': 'Safety tip classification',
  'SFS': 'Spam filter rules that matched',
  'DIR': 'Direction (INB=inbound, OUT=outbound)',
  'SFP': 'Spam filter policy applied',
  'COUNTRY': 'Sender country code',
  'REGION': 'Sender region',
  'SOURCE': 'Message source',
  'BCL': 'Bulk Complaint Level (0=not bulk, 9=definite bulk)',
  'EDV': 'Exchange Detection Version',
  'AMP': 'Anti-malware policy applied',
};

/** Parse structured header values (semicolon or comma separated key=value). */
export function parseStructuredValue(val: string): { key: string; value: string; hint?: string }[] | null {
  const parts = val.split(';').map(s => s.trim()).filter(Boolean);
  if (parts.length < 2) return null;

  const parsed: { key: string; value: string; hint?: string }[] = [];
  for (const part of parts) {
    const eqIdx = part.indexOf(':');
    const eqIdx2 = part.indexOf('=');
    const splitIdx = eqIdx >= 0 && (eqIdx2 < 0 || eqIdx < eqIdx2) ? eqIdx : eqIdx2;
    if (splitIdx > 0) {
      const k = part.slice(0, splitIdx).trim();
      const v = part.slice(splitIdx + 1).trim();
      parsed.push({ key: k, value: v, hint: ANTISPAM_FIELDS[k.toUpperCase()] });
    } else {
      parsed.push({ key: part, value: '', hint: undefined });
    }
  }
  return parsed.length >= 2 ? parsed : null;
}

/** Headers that contain opaque encrypted/encoded blobs — not human-readable. */
export const OPAQUE_HEADERS = new Set([
  'x-microsoft-antispam-message-info',
  'x-ms-exchange-message-sentrepresentingtype',
  'x-ms-exchange-crosstenant-originalarrivaltime',
  'x-ms-exchange-transport-crosstenantheadersstamped',
]);

/** Check if a header value looks like an opaque blob (long base64-like content). */
export function isOpaqueBlob(key: string, value: string): boolean {
  if (OPAQUE_HEADERS.has(key.toLowerCase())) return true;
  if (value.length > 500 && /^[A-Za-z0-9+/=\s]{500,}$/.test(value.replace(/\s+/g, ''))) return true;
  return false;
}

/** Format a header value for display: decode, then smart-format if structured. */
export function formatHeaderValue(key: string, rawVal: string): { decoded: string; structured: { key: string; value: string; hint?: string }[] | null; opaque: boolean } {
  const decoded = decodeRFC2047(rawVal);
  const lowerKey = key.toLowerCase();

  if (isOpaqueBlob(key, decoded)) {
    return { decoded, structured: null, opaque: true };
  }

  if (lowerKey === 'x-forefront-antispam-report' ||
      lowerKey === 'authentication-results' ||
      lowerKey === 'x-microsoft-antispam') {
    const structured = parseStructuredValue(decoded);
    if (structured) return { decoded, structured, opaque: false };
  }

  return { decoded, structured: null, opaque: false };
}
