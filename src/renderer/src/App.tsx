import React, { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import type { InvestigationSession, ProxyConfig, AuthUser, AuthState, UpdateState } from './types';
import { Sidebar } from './components/Sidebar';
import { Workspace } from './components/Workspace';
import { ProxyModal } from './components/ProxyModal';
import { TopBar } from './components/TopBar';
import { CaseNameModal } from './components/CaseNameModal';
import { LoginScreen } from './components/LoginScreen';
import { SettingsPage } from './components/SettingsPage';
import ChatPanel from './components/ChatPanel';

class PanelErrorBoundary extends React.Component<{children: React.ReactNode; name?: string}, {hasError: boolean; error?: string}> {
  state: {hasError: boolean; error?: string} = { hasError: false };
  static getDerivedStateFromError(error: Error) { return { hasError: true, error: error.message }; }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center h-full p-4">
          <div className="text-center">
            <p className="text-xs text-[color:var(--st-text-muted)] mb-2">
              {this.props.name || 'Panel'} failed to load.
            </p>
            <p className="text-[10px] text-[color:var(--st-text-muted)] font-mono mb-3 opacity-60">
              {this.state.error}
            </p>
            <button
              onClick={() => this.setState({ hasError: false, error: undefined })}
              className="text-xs text-[color:var(--st-accent)] underline cursor-pointer"
            >
              Retry
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
import { ThreatLevelProvider } from './contexts/ThreatLevelContext';
import { CommandPalette } from './components/CommandPalette';
import { useCommandPalette } from './hooks/useCommandPalette';
import { Dashboard } from './components/dashboard/Dashboard';
import { Button } from './components/ui/button';

function formatProxyStatus(config: ProxyConfig): string {
  return config.type === 'direct'
    ? 'Direct connection (no proxy)'
    : `Proxy: ${config.type}://${config.host}:${config.port} ${config.region ? `(${config.region})` : ''}`;
}

export default function App() {
  const [sessions, setSessions] = useState<InvestigationSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig | null>(null);
  const [showProxyModal, setShowProxyModal] = useState(false);
  const [showCaseNameModal, setShowCaseNameModal] = useState(false);
  const [pendingCaseId, setPendingCaseId] = useState('');
  const [showCloseConfirm, setShowCloseConfirm] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [authState, setAuthState] = useState<AuthState>('authenticated');  // Skip login gate — app works without auth
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [showLoginForChat, setShowLoginForChat] = useState(false);  // Login only when chat requires it
  const [avatar, setAvatar] = useState(localStorage.getItem('shieldtier-avatar') || 'shield');
  const [localAnalystName, setLocalAnalystName] = useState('');
  const [showNamePrompt, setShowNamePrompt] = useState(false);
  const [nameLoaded, setNameLoaded] = useState(false);
  const [nameInput, setNameInput] = useState('');
  const [status, setStatus] = useState<string>('No proxy configured');

  // Chat state — app-level so it's always available
  const [chatOpen, setChatOpen] = useState(false);
  const [chatHeight, setChatHeight] = useState(() => {
    const saved = localStorage.getItem('shieldtier-chat-height');
    return saved ? parseInt(saved, 10) || 300 : 300;
  });
  const [chatResizing, setChatResizing] = useState(false);
  const chatUnreadRef = useRef(0);
  const [chatUnread, setChatUnread] = useState(0);

  // Auto-update state
  const [updateState, setUpdateState] = useState<UpdateState | null>(null);

  const activeSession = sessions.find(s => s.id === activeSessionId) || null;
  const analystName = authUser?.analystName || authUser?.name || localAnalystName;

  // Track chat unread count — active when user is logged in
  useEffect(() => {
    if (!authUser) return;
    const unsub = window.shieldtier.chat.onMessageReceived(() => {
      if (!chatOpen) {
        chatUnreadRef.current++;
        setChatUnread(chatUnreadRef.current);
      }
    });
    return () => { unsub(); };
  }, [chatOpen, authState]);

  const handleToggleChat = useCallback(() => {
    // Require login for chat
    if (!authUser) {
      setShowLoginForChat(true);
      return;
    }
    setChatOpen(prev => {
      if (!prev) {
        // Opening chat — reset unread
        chatUnreadRef.current = 0;
        setChatUnread(0);
      }
      return !prev;
    });
  }, []);

  // Apply UI preferences (theme, font) on mount — runs before auth to prevent flash
  useEffect(() => {
    (async () => {
      try {
        const uiPrefs = await window.shieldtier.config.get('ui');
        if (uiPrefs) {
          // Theme
          const theme = uiPrefs.theme || 'dark';
          document.documentElement.setAttribute('data-theme', theme);

          // Font size
          const sizeMap: Record<string, number> = { small: 13, default: 14, large: 16 };
          const px = sizeMap[uiPrefs.fontSize] ?? 14;
          document.documentElement.style.setProperty('--st-font-size-base', `${px}px`);

          // Font family
          if (uiPrefs.fontFamily === 'system') {
            document.documentElement.style.setProperty(
              '--font-sans',
              "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
            );
          }
        }
      } catch {}
    })();
  }, []);

  // First-run: load analyst name from C++ config store (persists to disk)
  useEffect(() => {
    (async () => {
      try {
        const saved = await window.shieldtier.config.get('analystName');
        if (saved && typeof saved === 'string' && saved.trim()) {
          setLocalAnalystName(saved.trim());
        } else {
          setShowNamePrompt(true);
        }
      } catch {
        setShowNamePrompt(true);
      }
      setNameLoaded(true);
    })();
  }, []);

  // Restore session on mount: try auth silently in background, load config regardless
  useEffect(() => {
    (async () => {
      // Load proxy config — doesn't require auth
      try {
        const saved = await window.shieldtier.config.getProxyConfig();
        if (saved) {
          setProxyConfig(saved);
          setStatus(formatProxyStatus(saved));
        }
      } catch {}

      // Try to silently restore auth session (background, non-blocking)
      try {
        const authResult = await window.shieldtier.auth.restoreSession();
        if (authResult.success && authResult.user) {
          setAuthUser(authResult.user);
          // Fetch fresh profile
          try {
            const freshProfile = await window.shieldtier.auth.refreshProfile();
            if (freshProfile.success && freshProfile.user) {
              setAuthUser(freshProfile.user);
              if (freshProfile.user.avatar) {
                setAvatar(freshProfile.user.avatar);
                localStorage.setItem('shieldtier-avatar', freshProfile.user.avatar);
              }
            }
          } catch {}
          // Init chat identity if logged in
          window.shieldtier.chat.getIdentity().catch(() => null);
        }
        // If auth fails, that's fine — app still works, chat will prompt login
      } catch {}
    })();
  }, []);

  // Listen for session expiry
  useEffect(() => {
    const cleanup = window.shieldtier.auth.onSessionExpired(() => {
      setAuthState('unauthenticated');
      setAuthUser(null);
    });
    return cleanup;
  }, []);

  // Auto-check for updates on mount (no auth required)
  useEffect(() => {
    window.shieldtier.update.check().catch(() => {});
    const unsub = window.shieldtier.update.onStatus((state: UpdateState) => {
      setUpdateState(state);
    });
    return unsub;
  }, []);

  const handleAuthenticated = useCallback(async (user: AuthUser) => {
    setAuthUser(user);
    setAuthState('authenticated');
    // Load avatar from server profile
    if (user.avatar) {
      setAvatar(user.avatar);
      localStorage.setItem('shieldtier-avatar', user.avatar);
    }

    // Now load proxy config and chat identity
    try {
      const saved = await window.shieldtier.config.getProxyConfig();
      if (saved) {
        setProxyConfig(saved);
        setStatus(formatProxyStatus(saved));
      }
    } catch {}
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await window.shieldtier.auth.logout();
    } catch {}
    setAuthUser(null);
    setAuthState('unauthenticated');
    setSessions([]);
    setActiveSessionId(null);
    setChatOpen(false);
    setShowSettings(false);
  }, []);

  const handleNewSession = useCallback(async () => {
    if (!proxyConfig) {
      setShowProxyModal(true);
      return;
    }
    const nextId = await window.shieldtier.config.peekNextCaseId();
    setPendingCaseId(nextId);
    setShowCaseNameModal(true);
  }, [proxyConfig]);

  const handleCreateSessionWithName = useCallback(async (caseName: string) => {
    setShowCaseNameModal(false);
    try {
      const session = await window.shieldtier.session.create({ caseName });
      setSessions(prev => [...prev, session]);
      setActiveSessionId(session.id);
      setStatus(`Session created: ${caseName}`);
    } catch (err: any) {
      setStatus(`Error: ${err.message}`);
    }
  }, []);

  const handleRequestDestroySession = useCallback((sessionId: string) => {
    setShowCloseConfirm(sessionId);
  }, []);

  const handleDestroySession = useCallback(async (sessionId: string) => {
    setShowCloseConfirm(null);
    try {
      await window.shieldtier.session.destroy(sessionId);
      setSessions(prev => {
        const remaining = prev.filter(s => s.id !== sessionId);
        setActiveSessionId(prevActive =>
          prevActive === sessionId ? (remaining[0]?.id || null) : prevActive
        );
        return remaining;
      });
      setStatus(`Session ${sessionId.slice(0, 8)} destroyed — all data wiped`);
    } catch (err: any) {
      setStatus(`Error destroying session: ${err.message}`);
    }
  }, []);

  const handleSaveAndClose = useCallback(async (sessionId: string) => {
    setShowCloseConfirm(null);
    const session = sessions.find(s => s.id === sessionId);
    const label = session?.caseName || sessionId.slice(0, 8);
    setStatus(`Exporting session "${label}"...`);
    try {
      const result = await window.shieldtier.report.generate({
        sessionId,
        format: 'zip',
        title: `Session Export — ${label}`,
        analystName,
        analystNotes: 'Auto-saved on session close.',
        sections: {
          networkAnalysis: true,
          iocIntelligence: true,
          fileAnalysis: true,
          visualEvidence: true,
          timeline: true,
        },
        options: {
          includeScreenshots: true,
          includeDOMSnapshots: true,
          includeRawHAR: true,
        },
        timelineEvents: [],
      });
      if (result.success) {
        setStatus(`Session "${label}" saved and exported`);
      } else {
        setStatus(`Export error: ${result.error}`);
      }
    } catch (err: any) {
      setStatus(`Export error: ${err.message}`);
    }
    await handleDestroySession(sessionId);
  }, [sessions, analystName, handleDestroySession]);

  const handleProxyConfigured = useCallback(async (config: ProxyConfig) => {
    try {
      const result = await window.shieldtier.proxy.configure(config);
      if (result.success) {
        setProxyConfig(config);
        setShowProxyModal(false);
        setStatus(formatProxyStatus(config));
      }
    } catch (err: any) {
      setStatus(`Proxy error: ${err.message}`);
    }
  }, []);

  // Settings proxy handler — configures proxy from settings page
  const handleSettingsProxyConfigured = useCallback(async (config: ProxyConfig) => {
    await handleProxyConfigured(config);
  }, [handleProxyConfigured]);

  const anyModalOpen = showProxyModal || showCaseNameModal || showCloseConfirm !== null || showSettings;

  // Command Palette (Cmd+K)
  const cmdPalette = useCommandPalette({
    onNewSession: handleNewSession,
    onOpenSettings: () => setShowSettings(true),
    onConfigureProxy: () => setShowProxyModal(true),
    onToggleChat: handleToggleChat,
    hasActiveSession: !!activeSession,
  });

  // Threat signals — derived from active session data.
  // Workspace will populate these once component migration (Phase 6) wires them.
  const threatSignals = useMemo(() => ({
    iocVerdicts: [] as any[],
    fileRiskLevels: [] as any[],
    sandboxScores: [] as number[],
    phishingVerdict: null,
    threatFeedMatches: 0,
  }), []);

  // ── Chat requires login — show login modal when chat is opened without auth ──
  const handleChatToggle = useCallback(() => {
    if (!authUser) {
      // Not logged in — show login prompt for chat
      setShowLoginForChat(true);
      return;
    }
    setChatOpen(prev => !prev);
  }, [authUser]);

  // After login from chat prompt, open chat automatically
  const handleChatLoginSuccess = useCallback(async (user: AuthUser) => {
    setAuthUser(user);
    setShowLoginForChat(false);
    // Init chat identity
    try { await window.shieldtier.chat.getIdentity(); } catch {}
    setChatOpen(true);
  }, []);

  // First-run name prompt
  // Wait for name to load before rendering (prevents flash of "Analyst")
  if (!nameLoaded) {
    return (
      <div className="h-screen w-screen bg-[color:var(--st-bg-base)] flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-2 border-purple-500/30 border-t-purple-500 rounded-full" />
      </div>
    );
  }

  if (showNamePrompt) {
    return (
      <div className="flex items-center justify-center h-screen bg-[color:var(--st-bg-base)]">
        <div className="text-center max-w-sm mx-auto p-8">
          {/* Shield logo */}
          <div className="flex justify-center mb-6">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
              <defs>
                <linearGradient id="sg" x1="16" y1="8" x2="48" y2="56" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#3b82f6" /><stop offset="0.5" stopColor="#8b5cf6" /><stop offset="1" stopColor="#06b6d4" />
                </linearGradient>
              </defs>
              <path d="M32 4L8 16v16c0 14.4 10.2 27.2 24 30 13.8-2.8 24-15.6 24-30V16L32 4z" stroke="url(#sg)" strokeWidth="2.5" fill="none" />
              <path d="M32 14L14 22v10c0 10.8 7.6 20.4 18 22.5 10.4-2.1 18-11.7 18-22.5V22L32 14z" fill="url(#sg)" opacity="0.15" />
              <path d="M24 32l5 5 11-11" stroke="url(#sg)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h1 className="text-xl font-bold text-[color:var(--st-text-primary)] mb-1">Welcome to ShieldTier</h1>
          <p className="text-xs text-[color:var(--st-text-muted)] mb-6">Enter your analyst name to get started. This will appear in your investigation reports.</p>
          <input
            type="text"
            value={nameInput}
            onChange={e => setNameInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && nameInput.trim()) {
                window.shieldtier.config.set('analystName', nameInput.trim());
                setLocalAnalystName(nameInput.trim());
                setShowNamePrompt(false);
              }
            }}
            placeholder="Your name (e.g. John Smith)"
            autoFocus
            className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded-lg px-4 py-2.5 text-sm text-[color:var(--st-text-primary)] placeholder-[color:var(--st-text-muted)] focus:border-blue-500/50 outline-none mb-4"
          />
          <button
            onClick={() => {
              if (nameInput.trim()) {
                window.shieldtier.config.set('analystName', nameInput.trim());
                setLocalAnalystName(nameInput.trim());
                setShowNamePrompt(false);
              }
            }}
            disabled={!nameInput.trim()}
            className="w-full py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  // Login screen for chat — modal overlay, not blocking the app
  if (showLoginForChat) {
    return (
      <>
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
          <div className="relative">
            <button
              onClick={() => setShowLoginForChat(false)}
              className="absolute top-2 right-2 z-10 text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] text-lg"
            >
              ✕
            </button>
            <LoginScreen onAuthenticated={handleChatLoginSuccess} />
          </div>
        </div>
      </>
    );
  }

  // ── Main App (always accessible — no login gate) ──
  return (
    <ThreatLevelProvider signals={threatSignals}>
    <div className="flex flex-col h-screen bg-[color:var(--st-bg-base)]">
      <TopBar
        proxyConfig={proxyConfig}
        status={status}
        analystName={analystName}
        avatar={avatar}
        chatOpen={chatOpen}
        chatUnread={chatUnread}
        onConfigureProxy={() => setShowProxyModal(true)}
        onLogout={handleLogout}
        onOpenSettings={() => setShowSettings(true)}
        onToggleChat={handleToggleChat}
      />

      {/* Auto-update notification banner */}
      {updateState?.status === 'available' && (
        <div className="flex items-center justify-between px-4 py-1.5 bg-[color:var(--st-info)]/90 text-white text-xs">
          <span>ShieldTier v{updateState.availableVersion} is available</span>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 text-xs text-white hover:bg-white/20"
            onClick={() => window.shieldtier.update.download()}
          >
            Download
          </Button>
        </div>
      )}
      {updateState?.status === 'downloading' && (
        <div className="flex items-center gap-3 px-4 py-1.5 bg-[color:var(--st-info)]/90 text-white text-xs">
          <span>Downloading update... {updateState.downloadProgress}%</span>
          <div className="flex-1 max-w-xs h-1 bg-white/20 rounded-full overflow-hidden">
            <div
              className="h-full bg-white rounded-full transition-all duration-300"
              role="progressbar"
              aria-valuenow={updateState.downloadProgress}
              aria-valuemin={0}
              aria-valuemax={100}
              style={{ width: `${updateState.downloadProgress}%` }}
            />
          </div>
        </div>
      )}
      {updateState?.status === 'downloaded' && (
        <div className="flex items-center justify-between px-4 py-1.5 bg-[color:var(--st-success)]/90 text-white text-xs">
          <span>Update ready — restart to apply v{updateState.availableVersion}</span>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 text-xs text-white hover:bg-white/20"
            onClick={() => window.shieldtier.update.install()}
          >
            Restart &amp; Update
          </Button>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        {sessions.length > 0 && (
          <Sidebar
            sessions={sessions}
            activeSessionId={activeSessionId}
            onSelectSession={(id) => { setShowSettings(false); setActiveSessionId(id); }}
            onDestroySession={handleRequestDestroySession}
            onNewSession={handleNewSession}
          />
        )}

        <div className="flex-1 flex flex-col overflow-hidden">
          <main className="flex-1 overflow-hidden">
            {showSettings && authUser ? (
              <PanelErrorBoundary name="Settings"><SettingsPage
                user={authUser}
                avatar={avatar}
                proxyConfig={proxyConfig}
                onAvatarChange={(newAvatar) => {
                  setAvatar(newAvatar);
                  localStorage.setItem('shieldtier-avatar', newAvatar);
                }}
                onUserUpdated={(updatedUser) => setAuthUser(updatedUser)}
                onProxyConfigured={handleSettingsProxyConfigured}
                onClose={() => setShowSettings(false)}
                onLogout={() => { setShowSettings(false); handleLogout(); }}
              /></PanelErrorBoundary>
            ) : activeSession ? (
              <PanelErrorBoundary name="Workspace">
                <Workspace session={activeSession} modalOpen={anyModalOpen || chatOpen} />
              </PanelErrorBoundary>
            ) : (
              <PanelErrorBoundary name="Dashboard">
                <Dashboard
                  hasProxy={!!proxyConfig}
                  analystName={analystName}
                  sessionCount={sessions.length}
                  onNewSession={handleNewSession}
                  onConfigureProxy={() => setShowProxyModal(true)}
                  onOpenSettings={() => setShowSettings(true)}
                />
              </PanelErrorBoundary>
            )}
          </main>

          {/* Chat Panel — always available, independent of sessions */}
          {chatOpen && !showSettings && (
            <PanelErrorBoundary name="Chat">
              <ChatPanel
                height={chatHeight}
                onResize={(h) => {
                  setChatHeight(h);
                  localStorage.setItem('shieldtier-chat-height', String(h));
                }}
                onResizeStart={() => setChatResizing(true)}
                onResizeEnd={() => setChatResizing(false)}
                collapsed={false}
                onToggleCollapse={() => setChatOpen(false)}
              />
            </PanelErrorBoundary>
          )}
        </div>
      </div>

      {showProxyModal && (
        <ProxyModal
          currentConfig={proxyConfig}
          onSave={handleProxyConfigured}
          onClose={() => setShowProxyModal(false)}
        />
      )}

      {showCaseNameModal && (
        <CaseNameModal
          caseId={pendingCaseId}
          onSubmit={handleCreateSessionWithName}
          onCancel={() => setShowCaseNameModal(false)}
        />
      )}

      {showCloseConfirm !== null && (
        <CloseConfirmModal
          sessionId={showCloseConfirm}
          caseName={sessions.find(s => s.id === showCloseConfirm)?.caseName}
          onSaveAndClose={() => handleSaveAndClose(showCloseConfirm)}
          onCloseWithoutSaving={() => handleDestroySession(showCloseConfirm)}
          onCancel={() => setShowCloseConfirm(null)}
        />
      )}

      <CommandPalette
        open={cmdPalette.open}
        onOpenChange={cmdPalette.setOpen}
        commands={cmdPalette.commands}
      />
    </div>
    </ThreatLevelProvider>
  );
}

function CloseConfirmModal({ sessionId, caseName, onSaveAndClose, onCloseWithoutSaving, onCancel }: {
  sessionId: string;
  caseName?: string;
  onSaveAndClose: () => void;
  onCloseWithoutSaving: () => void;
  onCancel: () => void;
}) {
  const label = caseName || `Session ${sessionId.slice(0, 8)}`;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center animate-fade-in" onClick={onCancel}>
      <div
        className="glass rounded-xl border w-[400px] max-w-[90vw] dialog-enter"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-5 py-4">
          <h3 className="text-sm font-semibold text-[color:var(--st-text-primary)] mb-2">Close Investigation</h3>
          <p className="text-xs text-[color:var(--st-text-secondary)]">
            Save session data for <span className="text-[color:var(--st-text-primary)] font-medium">"{label}"</span> locally before closing?
          </p>
        </div>
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-white/8">
          <Button variant="ghost" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button size="sm" onClick={onSaveAndClose}>
            Save & Close
          </Button>
          <Button variant="destructive" size="sm" onClick={onCloseWithoutSaving}>
            Close Without Saving
          </Button>
        </div>
      </div>
    </div>
  );
}

