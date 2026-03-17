import React, { useState, useEffect } from 'react';
import type { InvestigationSession } from '../types';
import { ReportModal } from './ReportModal';
import { EmailPanel } from './EmailPanel';
import { VerticalTabBar } from './VerticalTabBar';
import type { PanelTab } from './VerticalTabBar';

import MITREPanel from './MITREPanel';
import ThreatFeedPanel from './ThreatFeedPanel';
import AnalysisReportPanel from './AnalysisReportPanel';
import VMSandboxPanel from './VMSandboxPanel';
import LogAnalysisPanel from './LogAnalysisPanel';

import { useSessionData } from '../hooks/useSessionData';
import { useThreatLevel } from '../contexts/ThreatLevelContext';
import { BrowserPanel } from './panels/BrowserPanel';
import { NetworkPanel } from './panels/NetworkPanel';
import { ScreenshotsPanel } from './panels/ScreenshotsPanel';
import { TimelinePanel } from './panels/TimelinePanel';
import { AnalysisPanel } from './panels/AnalysisPanel';
import { FilesPanel } from './panels/FilesPanel';

interface WorkspaceProps {
  session: InvestigationSession;
  modalOpen?: boolean;
}

export function Workspace({ session, modalOpen }: WorkspaceProps) {
  const [activePanel, setActivePanel] = useState<PanelTab>('browser');
  const data = useSessionData(session);
  const { threatLevel } = useThreatLevel();

  // Hide BrowserView when not on browser tab or when modal overlays are open
  useEffect(() => {
    if (activePanel !== 'browser' || data.showReportModal || modalOpen) {
      window.shieldtier.view.hide(session.id);
    } else {
      window.dispatchEvent(new Event('resize'));
    }
    return () => { window.shieldtier.view.hide(session.id); };
  }, [activePanel, session.id, data.showReportModal, modalOpen]);

  const badges: Partial<Record<PanelTab, number>> = {
    network: data.captureStats.harEntries || undefined,
    screenshots: data.captureStats.screenshots || undefined,
    timeline: data.timelineEvents.length || undefined,
    analysis: (data.enrichmentCount + data.contentFindingCount) || undefined,
    sandbox: data.sandboxSignatureCount || undefined,
    files: data.quarantinedFiles.size || undefined,
    mitre: data.mitreCount || undefined,
    email: data.emailCount || undefined,
    logs: data.logAnalysisCount || undefined,
    threatfeed: data.threatFeedMatchCount || undefined,
  };

  return (
    <div className="flex flex-row h-full">
      {/* Vertical Tab Bar */}
      <VerticalTabBar
        activePanel={activePanel}
        onSelectPanel={setActivePanel}
        badges={badges}
        captureEnabled={data.captureEnabled}
        onOpenReport={() => data.setShowReportModal(true)}
      />

      {/* Content area */}
      <div className="flex-1 flex flex-col overflow-hidden" style={{ background: 'var(--st-bg-base)' }}>
        {/* Session info bar — clean macOS status strip */}
        <div
          className="flex items-center gap-2.5 px-3 py-1 border-b border-[color:var(--st-border)] text-[11px] text-[color:var(--st-text-muted)] shrink-0"
          style={{ background: 'var(--st-bg-elevated)' }}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${data.viewReady ? 'bg-[color:var(--st-success)]' : 'bg-[color:var(--st-warning)]'}`}
            aria-hidden="true"
          />
          <span className="font-medium">{data.viewReady ? 'Ready' : 'Loading'}</span>
          <span className="w-px h-3 bg-[color:var(--st-border)]" />
          <span className="font-mono">{session.caseId || session.id.slice(0, 8)}</span>
          {session.proxyConfig && (
            <>
              <span className="w-px h-3 bg-[color:var(--st-border)]" />
              <span className="text-[color:var(--st-success)]">
                {session.proxyConfig.type}://{session.proxyConfig.host}:{session.proxyConfig.port}
              </span>
            </>
          )}
          {session.caseName && (
            <>
              <span className="w-px h-3 bg-[color:var(--st-border)]" />
              <span className="text-[color:var(--st-text-secondary)] truncate max-w-xs">{session.caseName}</span>
            </>
          )}
          {threatLevel !== 'clean' && (
            <span
              className="text-[color:var(--st-accent)] uppercase text-[10px] font-bold tracking-wider ml-auto"
              role="status"
              aria-live="polite"
            >
              {threatLevel}
            </span>
          )}
        </div>

        {/* Panel content */}
        <div className="flex-1 overflow-hidden">
          {activePanel === 'browser' && (
            <BrowserPanel
              session={session}
              navState={data.navState}
              loadError={data.loadError}
              viewReady={data.viewReady}
              captureEnabled={data.captureEnabled}
              onToggleCapture={data.handleToggleCapture}
              onScreenshot={data.handleScreenshot}
              onDOMSnapshot={data.handleDOMSnapshot}
            />
          )}
          {activePanel === 'network' && (
            <NetworkPanel
              entries={data.liveHAREntries}
              captureEnabled={data.captureEnabled}
              onToggleCapture={data.handleToggleCapture}
              onExportHAR={data.handleExportHAR}
            />
          )}
          {activePanel === 'screenshots' && (
            <ScreenshotsPanel
              screenshots={data.screenshots}
              domSnapshots={data.domSnapshots}
              captureEnabled={data.captureEnabled}
              onScreenshot={data.handleScreenshot}
              onDOMSnapshot={data.handleDOMSnapshot}
            />
          )}
          {activePanel === 'timeline' && <TimelinePanel events={data.timelineEvents} />}
          {activePanel === 'analysis' && <AnalysisPanel session={session} />}
          {activePanel === 'sandbox' && <AnalysisReportPanel files={data.quarantinedFiles} />}
          {activePanel === 'vm-sandbox' && <VMSandboxPanel session={session} files={data.quarantinedFiles} />}
          {activePanel === 'files' && <FilesPanel session={session} files={data.quarantinedFiles} />}
          {activePanel === 'email' && <EmailPanel session={session} />}
          {activePanel === 'logs' && <LogAnalysisPanel session={session} />}
          {activePanel === 'mitre' && <MITREPanel session={session} files={data.quarantinedFiles} />}
          {activePanel === 'threatfeed' && <ThreatFeedPanel session={session} />}
        </div>
      </div>

      {/* Report Modal */}
      {data.showReportModal && (
        <ReportModal
          sessionId={session.id}
          sessionName={session.caseName || ''}
          caseId={session.caseId || ''}
          screenshots={data.screenshots}
          domSnapshots={data.domSnapshots}
          timelineEvents={data.timelineEvents}
          captureStats={data.captureStats}
          enrichmentCount={data.enrichmentCount}
          fileCount={data.quarantinedFiles.size}
          onClose={() => data.setShowReportModal(false)}
        />
      )}
    </div>
  );
}
