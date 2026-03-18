/**
 * useSessionData — Manages all per-session state (nav, capture, HAR, screenshots, badges, etc.).
 * Extracted from Workspace.tsx during Phase 2 decomposition.
 */

import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import type { InvestigationSession, NavigationState, LoadError, HAREntry, Screenshot, DOMSnapshot, QuarantinedFile, SandboxResult } from '../types';
import type { TimelineEvent } from '../components/panels/panel-types';

export interface SessionData {
  // Navigation
  navState: NavigationState | null;
  loadError: LoadError | null;
  viewReady: boolean;

  // Timeline
  timelineEvents: TimelineEvent[];

  // Capture
  captureEnabled: boolean;
  captureStats: { harEntries: number; screenshots: number; domSnapshots: number };
  liveHAREntries: HAREntry[];
  screenshots: Screenshot[];
  domSnapshots: DOMSnapshot[];

  // Badge counts
  enrichmentCount: number;
  contentFindingCount: number;
  yaraMatchCount: number;
  emailCount: number;
  threatFeedMatchCount: number;
  logAnalysisCount: number;
  mitreCount: number;

  // File analysis
  quarantinedFiles: Map<string, QuarantinedFile>;

  // Live sandbox
  liveSandboxResult: SandboxResult | null;

  // Report modal
  showReportModal: boolean;
  setShowReportModal: (show: boolean) => void;

  // Capture controls
  handleToggleCapture: () => Promise<void>;
  handleScreenshot: () => Promise<void>;
  handleDOMSnapshot: () => Promise<void>;
  handleExportHAR: () => Promise<void>;

  // Computed
  sandboxSignatureCount: number;
}

export function useSessionData(session: InvestigationSession): SessionData {
  const [navState, setNavState] = useState<NavigationState | null>(null);
  const [loadError, setLoadError] = useState<LoadError | null>(null);
  const [viewReady, setViewReady] = useState(false);
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([
    { time: new Date(session.createdAt).toLocaleTimeString(), event: 'Session created', detail: `ID: ${session.id.slice(0, 8)}`, type: 'info' },
  ]);

  // Capture state — auto-enabled on session creation
  const [captureEnabled, setCaptureEnabled] = useState(true);
  const [captureStats, setCaptureStats] = useState({ harEntries: 0, screenshots: 0, domSnapshots: 0 });
  const [liveHAREntries, setLiveHAREntries] = useState<HAREntry[]>([]);
  const harBufferRef = useRef<HAREntry[]>([]);
  const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
  const [domSnapshots, setDOMSnapshots] = useState<DOMSnapshot[]>([]);

  // Enrichment IOC count for tab badge
  const [enrichmentCount, setEnrichmentCount] = useState(0);

  // Content findings count for tab badge
  const [contentFindingCount, setContentFindingCount] = useState(0);

  // File analysis state
  const [quarantinedFiles, setQuarantinedFiles] = useState<Map<string, QuarantinedFile>>(new Map());

  // YARA match count for tab badge
  const [yaraMatchCount, setYaraMatchCount] = useState(0);

  // Email count for tab badge
  const [emailCount, setEmailCount] = useState(0);

  // Threat feed match count for tab badge
  const [threatFeedMatchCount, setThreatFeedMatchCount] = useState(0);

  // Log analysis count for tab badge
  const [logAnalysisCount, setLogAnalysisCount] = useState(0);

  // MITRE technique count for tab badge (computed from quarantined files)
  const mitreCount = useMemo(() => {
    const techniques = new Set<string>();
    for (const [, file] of quarantinedFiles) {
      if (file.staticAnalysis?.findings) {
        for (const f of file.staticAnalysis.findings) {
          if (f.mitre) techniques.add(f.mitre);
        }
      }
      for (const sr of file.sandboxResults) {
        if (sr.details?.signatures) {
          for (const sig of sr.details.signatures as any[]) {
            if (sig.mitre) techniques.add(sig.mitre);
          }
        }
        if (sr.details?.advancedFindings) {
          for (const af of sr.details.advancedFindings as any[]) {
            if (af.mitre) techniques.add(af.mitre);
          }
        }
      }
    }
    return techniques.size;
  }, [quarantinedFiles]);

  // Live sandbox analysis result for current page (auto-triggered after page load)
  const [liveSandboxResult, setLiveSandboxResult] = useState<SandboxResult | null>(null);

  // Report modal state
  const [showReportModal, setShowReportModal] = useState(false);

  // Track threat feed match count
  useEffect(() => {
    // Load existing matches
    window.shieldtier.threatfeed.getMatches(session.id).then(m => setThreatFeedMatchCount(m.length)).catch(() => {});
    const unsub = window.shieldtier.threatfeed.onMatch((match) => {
      if (match.sessionId === session.id) {
        setThreatFeedMatchCount(prev => prev + 1);
      }
    });
    return () => { unsub(); };
  }, [session.id]);

  // Create BrowserView on mount + auto-enable capture (matches V1 behavior)
  useEffect(() => {
    let mounted = true;
    (async () => {
      const result = await window.shieldtier.view.create(session.id);
      if (mounted && result.success) {
        setViewReady(true);
      }
      // Auto-enable capture on session creation (V1 does this automatically)
      const captureResult = await window.shieldtier.capture.enable(session.id);
      if (mounted && captureResult.success) {
        setCaptureEnabled(true);
      }
    })();
    return () => { mounted = false; };
  }, [session.id]);

  // Listen for navigation state changes
  useEffect(() => {
    const unsubNav = window.shieldtier.view.onNavStateChanged((sessionId, state) => {
      if (sessionId === session.id) {
        setNavState(state);
        setLoadError(null);
      }
    });
    const unsubErr = window.shieldtier.view.onLoadError((sessionId, error) => {
      if (sessionId === session.id) {
        setLoadError(error);
        setTimelineEvents(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          event: `Load error: ${error.errorDescription}`,
          detail: error.url,
          type: 'danger',
        }]);
      }
    });
    const unsubSandbox = window.shieldtier.view.onSandboxResult((sessionId, result) => {
      if (sessionId === session.id) {
        setLiveSandboxResult(result);
      }
    });
    return () => { unsubNav(); unsubErr(); unsubSandbox(); };
  }, [session.id]);

  // Listen for live network events from CDP capture — batch updates to reduce re-renders
  useEffect(() => {
    let flushHandle: number | null = null;

    const flushBuffer = () => {
      flushHandle = null;
      if (harBufferRef.current.length === 0) return;
      const batch = harBufferRef.current;
      harBufferRef.current = [];
      setLiveHAREntries(prev => [...prev, ...batch].slice(-2000));
    };

    const unsub = window.shieldtier.capture.onNetworkEvent((sessionId, entry) => {
      if (sessionId === session.id) {
        harBufferRef.current.push(entry);
        setCaptureStats(prev => ({ ...prev, harEntries: prev.harEntries + 1 }));
        if (flushHandle === null) {
          flushHandle = requestAnimationFrame(flushBuffer);
        }
      }
    });
    return () => {
      unsub();
      if (flushHandle !== null) cancelAnimationFrame(flushHandle);
      // Flush remaining buffered entries
      if (harBufferRef.current.length > 0) {
        const remaining = harBufferRef.current;
        harBufferRef.current = [];
        setLiveHAREntries(prev => [...prev, ...remaining].slice(-2000));
      }
    };
  }, [session.id]);

  // Track enrichment IOC count for tab badge
  useEffect(() => {
    const seen = new Set<string>();
    const unsub = window.shieldtier.enrichment.onResult((sessionId, entry) => {
      if (sessionId === session.id) {
        seen.add(entry.value.toLowerCase());
        setEnrichmentCount(seen.size);
      }
    });
    // Load existing count
    (async () => {
      const results = await window.shieldtier.enrichment.getResults(session.id);
      for (const r of results) seen.add(r.value.toLowerCase());
      if (seen.size > 0) setEnrichmentCount(seen.size);
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Track content findings count for tab badge
  useEffect(() => {
    let count = 0;
    const unsub = window.shieldtier.contentanalysis.onFinding((sessionId) => {
      if (sessionId === session.id) {
        count++;
        setContentFindingCount(count);
      }
    });
    // Load existing count
    (async () => {
      const findings = await window.shieldtier.contentanalysis.getFindings(session.id);
      count = findings.length;
      if (count > 0) setContentFindingCount(count);
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Listen for file analysis updates
  useEffect(() => {
    const unsub = window.shieldtier.fileanalysis.onFileUpdate((sessionId, file) => {
      if (sessionId === session.id) {
        setQuarantinedFiles(prev => {
          const next = new Map(prev);
          next.set(file.id, file);
          return next;
        });
      }
    });
    // Load existing files
    (async () => {
      const files = await window.shieldtier.fileanalysis.getFiles(session.id);
      if (files.length > 0) {
        setQuarantinedFiles(prev => {
          const next = new Map(prev);
          for (const f of files) next.set(f.id, f);
          return next;
        });
      }
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Track YARA match count for badge
  useEffect(() => {
    const unsub = window.shieldtier.yara.onScanResult((sessionId, result) => {
      if (sessionId === session.id && result.matches.length > 0) {
        setYaraMatchCount(prev => prev + result.matches.length);
      }
    });
    // Load existing results
    (async () => {
      const results = await window.shieldtier.yara.getScanResults(session.id);
      const total = results.reduce((sum: number, r: any) => sum + r.matches.length, 0);
      if (total > 0) setYaraMatchCount(total);
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Track email count for badge
  useEffect(() => {
    const unsub = window.shieldtier.email.onEmailParsed((sessionId) => {
      if (sessionId === session.id) {
        setEmailCount(prev => prev + 1);
      }
    });
    // Load existing count
    (async () => {
      const emails = await window.shieldtier.email.getEmails(session.id);
      if (emails.length > 0) setEmailCount(emails.length);
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Log analysis count for badge
  useEffect(() => {
    const unsub = (window.shieldtier as any).loganalysis.onComplete((sessionId: string) => {
      if (sessionId === session.id) {
        setLogAnalysisCount(prev => prev + 1);
      }
    });
    // Load existing count
    (async () => {
      const results = await (window.shieldtier as any).loganalysis.getResults(session.id);
      if (results.length > 0) setLogAnalysisCount(results.length);
    })();
    return () => { unsub(); };
  }, [session.id]);

  // Add timeline event on navigation
  useEffect(() => {
    if (navState?.url && !navState.isLoading && navState.url !== 'about:blank') {
      setTimelineEvents(prev => {
        const last = prev[prev.length - 1];
        if (last?.detail === navState.url) return prev;
        return [...prev, {
          time: new Date().toLocaleTimeString(),
          event: navState.title || 'Page loaded',
          detail: navState.url,
          type: 'info',
        }];
      });
    }
  }, [navState?.url, navState?.isLoading, navState?.title]);

  // Capture controls
  const handleToggleCapture = useCallback(async () => {
    if (captureEnabled) {
      await window.shieldtier.capture.disable(session.id);
      setCaptureEnabled(false);
      setTimelineEvents(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        event: 'Capture stopped',
        detail: `${captureStats.harEntries} requests recorded`,
        type: 'warning',
      }]);
    } else {
      const result = await window.shieldtier.capture.enable(session.id);
      if (result.success) {
        setCaptureEnabled(true);
        setLiveHAREntries([]);
        setCaptureStats({ harEntries: 0, screenshots: 0, domSnapshots: 0 });
        setTimelineEvents(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          event: 'Capture started',
          detail: 'Recording network traffic, screenshots, DOM snapshots',
          type: 'info',
        }]);
      }
    }
  }, [captureEnabled, captureStats.harEntries, session.id]);

  const handleScreenshot = useCallback(async () => {
    const ss = await window.shieldtier.capture.takeScreenshot(session.id);
    if (ss) {
      setScreenshots(prev => [...prev, ss]);
      setCaptureStats(prev => ({ ...prev, screenshots: prev.screenshots + 1 }));
      setTimelineEvents(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        event: 'Screenshot captured',
        detail: ss.url,
        type: 'info',
      }]);
    }
  }, [session.id]);

  const handleDOMSnapshot = useCallback(async () => {
    const snap = await window.shieldtier.capture.takeDOMSnapshot(session.id);
    if (snap) {
      setDOMSnapshots(prev => [...prev, snap]);
      setCaptureStats(prev => ({ ...prev, domSnapshots: prev.domSnapshots + 1 }));
      setTimelineEvents(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        event: 'DOM snapshot captured',
        detail: snap.url,
        type: 'info',
      }]);
    }
  }, [session.id]);

  const handleExportHAR = useCallback(async () => {
    const har = await window.shieldtier.capture.getHAR(session.id);
    if (har) {
      const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `shieldtier-${session.id.slice(0, 8)}-${Date.now()}.har`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [session.id]);

  const sandboxSignatureCount = liveSandboxResult?.details?.signaturesFired || 0;

  return {
    navState,
    loadError,
    viewReady,
    timelineEvents,
    captureEnabled,
    captureStats,
    liveHAREntries,
    screenshots,
    domSnapshots,
    enrichmentCount,
    contentFindingCount,
    yaraMatchCount,
    emailCount,
    threatFeedMatchCount,
    logAnalysisCount,
    mitreCount,
    quarantinedFiles,
    liveSandboxResult,
    showReportModal,
    setShowReportModal,
    handleToggleCapture,
    handleScreenshot,
    handleDOMSnapshot,
    handleExportHAR,
    sandboxSignatureCount,
  };
}
