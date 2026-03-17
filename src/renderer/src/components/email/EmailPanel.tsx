// ---------------------------------------------------------------------------
// ShieldTier Email Panel — Orchestrator
// ---------------------------------------------------------------------------

import React, { useState, useEffect, useCallback, useRef } from 'react';
import type { ParsedEmail } from './email-types';
import { getScoreColor, getScoreBg, getVerdictLabel, getSeverityColor } from './email-utils';
import { PhishingScoreCard } from './PhishingScoreCard';
import { HeadersTab } from './HeadersTab';
import { BodyTab } from './BodyTab';
import { URLsTab } from './URLsTab';
import { AttachmentsTab } from './AttachmentsTab';
import { IndicatorsTab } from './IndicatorsTab';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/tabs';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { ScrollArea } from '../ui/scroll-area';

// ═══════════════════════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════════════════════

interface EmailPanelProps {
  session: { id: string };
}

export function EmailPanel({ session }: EmailPanelProps) {
  const [emails, setEmails] = useState<ParsedEmail[]>([]);
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<'overview' | 'headers' | 'body' | 'urls' | 'attachments' | 'indicators'>('overview');
  const [showPasteInput, setShowPasteInput] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [parseStage, setParseStage] = useState<'' | 'opening' | 'analyzing' | 'complete'>('');
  const parseStageRef = useRef(parseStage);
  parseStageRef.current = parseStage;
  const dropRef = useRef<HTMLDivElement>(null);

  const loadEmails = useCallback(async () => {
    const result = await window.shieldtier.email.getEmails(session.id);
    setEmails(result);
  }, [session.id]);

  useEffect(() => { loadEmails(); }, [loadEmails]);

  // Listen for parsed emails — fires twice per email:
  // Phase 1: immediately after MIME parse (headers, body visible — no phishingScore)
  // Phase 2: after full analysis (scores, indicators, enriched URLs)
  useEffect(() => {
    const unsub = window.shieldtier.email.onEmailParsed((_sessionId: string, email: ParsedEmail) => {
      if (_sessionId === session.id) {
        setEmails(prev => {
          const idx = prev.findIndex(e => e.id === email.id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = email;
            return next;
          }
          return [...prev, email];
        });
        // Phase 2 (has phishingScore) -> analysis complete
        if (email.phishingScore && parseStageRef.current === 'analyzing') {
          setParseStage('complete');
          setTimeout(() => setParseStage(''), 1500);
        }
      }
    });
    return () => { unsub(); };
  }, [session.id]);

  // Drag and drop
  useEffect(() => {
    const el = dropRef.current;
    if (!el) return;

    const handleDragOver = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      el.classList.add('ring-2', 'ring-cyan-500/30');
    };

    const handleDragLeave = () => {
      el.classList.remove('ring-2', 'ring-cyan-500/30');
    };

    const handleDrop = async (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      el.classList.remove('ring-2', 'ring-cyan-500/30');

      const files = e.dataTransfer?.files;
      if (files) {
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          if (file.name.endsWith('.eml') || file.type === 'message/rfc822') {
            setParseStage('opening');
            try {
              const text = await file.text();
              setParseStage('analyzing');
              await window.shieldtier.email.parseRaw(session.id, text);
              await loadEmails();
              setParseStage('complete');
              setTimeout(() => setParseStage(''), 1500);
            } catch {
              setParseStage('');
            }
          }
        }
      }
    };

    el.addEventListener('dragover', handleDragOver);
    el.addEventListener('dragleave', handleDragLeave);
    el.addEventListener('drop', handleDrop);

    return () => {
      el.removeEventListener('dragover', handleDragOver);
      el.removeEventListener('dragleave', handleDragLeave);
      el.removeEventListener('drop', handleDrop);
    };
  }, [session.id, loadEmails]);

  const handleOpenFile = async () => {
    setParseStage('opening');
    try {
      const result = await window.shieldtier.email.openFile(session.id);
      if (!result) {
        // User cancelled the dialog
        setParseStage('');
        return;
      }
      // Files selected — analysis runs in background, email:parsed event triggers completion
      setParseStage('analyzing');
    } catch {
      setParseStage('');
    }
  };

  const handlePasteSource = async () => {
    if (!pasteText.trim()) return;
    setParseStage('opening');
    try {
      setParseStage('analyzing');
      await window.shieldtier.email.parseRaw(session.id, pasteText);
      setPasteText('');
      setShowPasteInput(false);
      await loadEmails();
      setParseStage('complete');
      setTimeout(() => setParseStage(''), 1500);
    } catch {
      setParseStage('');
    }
  };

  const selectedEmail = selectedEmailId ? emails.find(e => e.id === selectedEmailId) : null;

  return (
    <div ref={dropRef} className="flex flex-col h-full bg-[color:var(--st-bg-base)] text-[color:var(--st-text-primary)] text-xs">
      {/* Toolbar */}
      <div className="flex items-center gap-1 px-3 py-1.5 border-b border-[color:var(--st-border)]">
        <Button
          onClick={handleOpenFile}
          disabled={parseStage !== '' && parseStage !== 'complete'}
          variant="outline"
          size="sm"
          aria-label="Open .eml file"
          className="bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600/30 border-cyan-500/30"
        >
          Open .eml
        </Button>
        <Button
          onClick={() => setShowPasteInput(!showPasteInput)}
          variant={showPasteInput ? 'outline' : 'ghost'}
          size="sm"
          aria-label="Paste email source"
          className={showPasteInput ? 'bg-cyan-600/20 text-cyan-400 border-cyan-500/30' : 'text-[color:var(--st-text-secondary)]'}
        >
          Paste Source
        </Button>
        <div className="flex-1" />
        <span className="text-[color:var(--st-text-muted)]">{emails.length} email{emails.length !== 1 ? 's' : ''}</span>
        <span className="text-[color:var(--st-text-muted)] text-[10px] ml-2">Drop .eml files here</span>
      </div>

      {/* Paste input area */}
      {showPasteInput && (
        <div className="px-3 py-2 border-b border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)]">
          <textarea
            value={pasteText}
            onChange={e => setPasteText(e.target.value)}
            placeholder="Paste raw email source here (RFC 5322 format)..."
            className="w-full h-24 bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded px-2 py-1 text-[color:var(--st-text-primary)] text-[10px] font-mono resize-none focus:border-cyan-500/50 outline-none"
          />
          <div className="flex justify-end mt-1">
            <Button
              onClick={handlePasteSource}
              disabled={!pasteText.trim() || (parseStage !== '' && parseStage !== 'complete')}
              variant="outline"
              size="sm"
              className="bg-cyan-600/30 text-cyan-400 hover:bg-cyan-600/40 border-cyan-500/30"
            >
              Parse
            </Button>
          </div>
        </div>
      )}

      {/* Split view */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: email list */}
        <div className="w-80 border-r border-[color:var(--st-border)] overflow-y-auto">
          {/* Stage indicators */}
          {parseStage && parseStage !== 'complete' && (
            <div className="px-3 py-2.5 border-b border-[color:var(--st-border-subtle)] bg-[color:var(--st-bg-panel)]" aria-live="polite">
              <div className="flex items-center gap-3">
                {/* Stage 1: Opening */}
                <div className="flex items-center gap-1.5">
                  {parseStage === 'opening' ? (
                    <div className="animate-spin w-3 h-3 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full" />
                  ) : (
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  )}
                  <span className={`text-[10px] ${parseStage === 'opening' ? 'text-cyan-400' : 'text-green-400'}`}>Opening</span>
                </div>
                <div className="w-4 h-px bg-[color:var(--st-border-subtle)]" />
                {/* Stage 2: Analyzing */}
                <div className="flex items-center gap-1.5">
                  {parseStage === 'analyzing' ? (
                    <div className="animate-spin w-3 h-3 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full" />
                  ) : (
                    <div className="w-3 h-3 rounded-full bg-[color:var(--st-border-subtle)]" />
                  )}
                  <span className={`text-[10px] ${parseStage === 'analyzing' ? 'text-cyan-400' : 'text-[color:var(--st-text-muted)]'}`}>Analyzing</span>
                </div>
                <div className="w-4 h-px bg-[color:var(--st-border-subtle)]" />
                {/* Stage 3: Complete */}
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-[color:var(--st-border-subtle)]" />
                  <span className="text-[10px] text-[color:var(--st-text-muted)]">Complete</span>
                </div>
              </div>
            </div>
          )}
          {parseStage === 'complete' && (
            <div className="px-3 py-2.5 border-b border-[color:var(--st-border-subtle)] bg-green-500/5">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="text-[10px] text-green-400">Opening</span>
                </div>
                <div className="w-4 h-px bg-green-500/30" />
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="text-[10px] text-green-400">Analyzing</span>
                </div>
                <div className="w-4 h-px bg-green-500/30" />
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="text-[10px] text-green-400">Complete</span>
                </div>
              </div>
            </div>
          )}
          {emails.length === 0 && !parseStage ? (
            <div className="flex flex-col items-center justify-center h-full text-[color:var(--st-text-muted)] text-sm gap-2">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="2" y="4" width="20" height="16" rx="2" />
                <path d="M22 7l-10 6L2 7" />
              </svg>
              <div>No emails analyzed</div>
              <div className="text-[10px] text-[color:var(--st-text-muted)]">Open .eml, paste source, or drag & drop</div>
            </div>
          ) : (
            emails.map(email => (
              <div
                key={email.id}
                onClick={() => { setSelectedEmailId(email.id); setDetailTab('overview'); }}
                className={`px-3 py-2 cursor-pointer border-b border-[color:var(--st-border-subtle)] hover:bg-[color:var(--st-bg-elevated)] ${
                  selectedEmailId === email.id ? 'bg-[color:var(--st-bg-elevated)] border-l-2 border-l-cyan-500' : ''
                }`}
              >
                <div className="flex items-center gap-2">
                  {/* Score circle */}
                  {email.phishingScore && (
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-[10px] font-bold border ${getScoreBg(email.phishingScore.score)}`}>
                      <span className={getScoreColor(email.phishingScore.score)}>{email.phishingScore.score}</span>
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="text-[color:var(--st-text-primary)] truncate" title={email.from}>{email.from}</div>
                    <div className="text-[color:var(--st-text-muted)] truncate" title={email.subject}>{email.subject}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[color:var(--st-text-muted)] text-[10px]">{email.date ? new Date(email.date).toLocaleDateString() : ''}</span>
                  {email.attachments.length > 0 && (
                    <span className="text-[9px] bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-muted)] px-1 rounded">
                      {email.attachments.length} att
                    </span>
                  )}
                  {email.phishingScore && (
                    <span className={`text-[9px] px-1.5 rounded ${getSeverityColor(
                      email.phishingScore.verdict === 'likely_phishing' ? 'critical' :
                      email.phishingScore.verdict === 'suspicious' ? 'medium' : 'info'
                    )}`}>
                      {getVerdictLabel(email.phishingScore.verdict)}
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right: detail */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {selectedEmail ? (
            <Tabs value={detailTab} onValueChange={(v) => setDetailTab(v as typeof detailTab)} className="flex flex-col flex-1 overflow-hidden">
              {/* Detail tabs */}
              <TabsList className="px-3 py-1.5 bg-[color:var(--st-bg-panel)]">
                {(['overview', 'headers', 'body', 'urls', 'attachments', 'indicators'] as const).map(tab => (
                  <TabsTrigger key={tab} value={tab} className="capitalize">
                    {tab}
                    {tab === 'urls' && selectedEmail.urls.length > 0 && (
                      <Badge size="sm" variant="outline" className="ml-1">{selectedEmail.urls.length}</Badge>
                    )}
                    {tab === 'attachments' && selectedEmail.attachments.length > 0 && (
                      <Badge size="sm" variant="outline" className="ml-1">{selectedEmail.attachments.length}</Badge>
                    )}
                    {tab === 'indicators' && selectedEmail.phishingScore && (
                      <Badge size="sm" variant="outline" className="ml-1">{selectedEmail.phishingScore.indicators.length}</Badge>
                    )}
                  </TabsTrigger>
                ))}
              </TabsList>

              {/* Detail content */}
              <ScrollArea className="flex-1">
                <div className="p-4">
                  <TabsContent value="overview" className="mt-0">
                    <PhishingScoreCard email={selectedEmail} />
                  </TabsContent>

                  <TabsContent value="headers" className="mt-0">
                    <HeadersTab email={selectedEmail} />
                  </TabsContent>

                  <TabsContent value="body" className="mt-0">
                    <BodyTab email={selectedEmail} />
                  </TabsContent>

                  <TabsContent value="urls" className="mt-0">
                    <URLsTab email={selectedEmail} />
                  </TabsContent>

                  <TabsContent value="attachments" className="mt-0">
                    <AttachmentsTab email={selectedEmail} sessionId={session.id} />
                  </TabsContent>

                  <TabsContent value="indicators" className="mt-0">
                    {selectedEmail.phishingScore && (
                      <IndicatorsTab phishingScore={selectedEmail.phishingScore} />
                    )}
                  </TabsContent>
                </div>
              </ScrollArea>
            </Tabs>
          ) : (
            <div className="flex items-center justify-center h-full text-[color:var(--st-text-muted)] text-sm">
              Select an email to view analysis
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
