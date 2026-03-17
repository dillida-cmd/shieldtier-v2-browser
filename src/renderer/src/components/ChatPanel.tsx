import React, { useState, useEffect, useCallback, useRef } from 'react';
import type { ChatContact, ChatMessage, ChatConnectionStatus, PresenceStatus } from '../types';
import { cn } from '../lib/utils';
import ChatContactList from './ChatContactList';
import ChatConversation from './ChatConversation';

const statusColorClass: Record<ChatConnectionStatus, string> = {
  connected: 'bg-[color:var(--st-success)]',
  connecting: 'bg-[color:var(--st-warning)]',
  disconnected: 'bg-gray-500',
  error: 'bg-[color:var(--st-danger)]',
};

const presenceColorClass: Record<PresenceStatus, string> = {
  online: 'bg-[color:var(--st-success)]',
  busy: 'bg-[color:var(--st-warning)]',
  offline: 'bg-gray-500',
};

interface ChatPanelProps {
  height: number;
  onResize: (newHeight: number) => void;
  onResizeStart: () => void;
  onResizeEnd: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export default function ChatPanel({
  height, onResize, onResizeStart, onResizeEnd, collapsed, onToggleCollapse,
}: ChatPanelProps) {
  const [identity, setIdentity] = useState<{ sessionId: string; mnemonic: string } | null>(null);
  const [contacts, setContacts] = useState<ChatContact[]>([]);
  const [messageRequests, setMessageRequests] = useState<ChatContact[]>([]);
  const [selectedContactId, setSelectedContactId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<ChatConnectionStatus>('disconnected');
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [ownPresence, setOwnPresence] = useState<PresenceStatus>('online');
  const [showPresenceMenu, setShowPresenceMenu] = useState(false);
  const dragStartY = useRef(0);
  const dragStartHeight = useRef(0);

  // Load identity + contacts + requests on mount
  useEffect(() => {
    window.shieldtier.chat.getIdentity().then(id => {
      setIdentity(id);
    }).catch(() => {});
    loadContacts().catch(() => {});
    loadRequests().catch(() => {});
    window.shieldtier.chat.getConnectionStatus().then(s => {
      if (s && typeof s === 'string') setConnectionStatus(s);
    }).catch(() => {});
  }, []);

  // Listen for events
  useEffect(() => {
    const unsubs: Array<() => void> = [];
    try {
      unsubs.push(
        window.shieldtier.chat.onMessageReceived((msg: any) => {
          if (msg.conversationId === selectedContactId) {
            setMessages(prev => [...prev, msg]);
            window.shieldtier.chat.markAsRead(msg.conversationId).catch(() => {});
          }
          loadContacts().catch(() => {});
        }),
        window.shieldtier.chat.onMessageSent((msg: any) => {
          setMessages(prev => prev.map(m => m.id === msg.id ? msg : m));
        }),
        window.shieldtier.chat.onMessageFailed(({ messageId }: any) => {
          setMessages(prev => prev.map(m => m.id === messageId ? { ...m, status: 'failed' as const } : m));
        }),
        window.shieldtier.chat.onIdentityCreated((data: any) => {
          setIdentity(data);
          setShowOnboarding(true);
        }),
        window.shieldtier.chat.onConnectionStatus(setConnectionStatus),
        window.shieldtier.chat.onPresenceUpdate(() => {
          loadContacts().catch(() => {});
        }),
        window.shieldtier.chat.onMessageRequest(() => {
          loadRequests().catch(() => {});
        }),
      );
    } catch {}
    return () => unsubs.forEach(fn => { try { fn(); } catch {} });
  }, [selectedContactId]);

  const loadContacts = useCallback(async () => {
    const c = await window.shieldtier.chat.getContacts();
    setContacts(c);
  }, []);

  const loadRequests = useCallback(async () => {
    try {
      const r = await window.shieldtier.chat.getMessageRequests();
      setMessageRequests(r);
    } catch {
      setMessageRequests([]);
    }
  }, []);

  const handleApproveContact = useCallback(async (sessionId: string) => {
    await window.shieldtier.chat.approveContact(sessionId);
    await loadContacts();
    await loadRequests();
  }, [loadContacts, loadRequests]);

  const handleRejectContact = useCallback(async (sessionId: string) => {
    await window.shieldtier.chat.rejectContact(sessionId);
    await loadRequests();
  }, [loadRequests]);

  // Load messages when contact selected
  useEffect(() => {
    if (!selectedContactId) {
      setMessages([]);
      return;
    }
    window.shieldtier.chat.getMessages(selectedContactId).then(setMessages);
    window.shieldtier.chat.markAsRead(selectedContactId);
  }, [selectedContactId]);

  const handleSend = useCallback(async (body: string) => {
    if (!selectedContactId) return;
    try {
      const msg = await window.shieldtier.chat.sendMessage(selectedContactId, body);
      setMessages(prev => [...prev, msg]);
    } catch {}
  }, [selectedContactId]);

  const handleAddContact = useCallback(async (sessionId: string, displayName: string) => {
    await window.shieldtier.chat.addContact(sessionId, displayName);
    await loadContacts();
  }, [loadContacts]);

  const handlePresenceChange = useCallback((status: PresenceStatus) => {
    setOwnPresence(status);
    setShowPresenceMenu(false);
    window.shieldtier.chat.setPresence(status);
  }, []);

  const acknowledgeOnboarding = useCallback(() => {
    setShowOnboarding(false);
    window.shieldtier.chat.acknowledgeOnboarding();
  }, []);

  // Drag resize handler
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragStartY.current = e.clientY;
    dragStartHeight.current = height;
    onResizeStart();

    const handleMouseMove = (ev: MouseEvent) => {
      const delta = dragStartY.current - ev.clientY;
      const newHeight = Math.max(200, Math.min(window.innerHeight * 0.6, dragStartHeight.current + delta));
      onResize(newHeight);
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      onResizeEnd();
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [height, onResize, onResizeStart, onResizeEnd]);

  const selectedContact = contacts.find(c => c.sessionId === selectedContactId);

  if (collapsed) return null;

  return (
    <div
      className="flex flex-col glass-heavy border-t border-[color:var(--st-glass-border)] relative"
      style={{ height }}
    >
      {/* Drag handle */}
      <div
        onMouseDown={handleMouseDown}
        className="h-1 cursor-ns-resize bg-[color:var(--st-accent-dim)] hover:bg-[color:var(--st-accent-glow)] absolute top-0 left-0 right-0 z-10 transition-colors"
      />

      {/* Header bar */}
      <div className="flex items-center gap-2 px-3 py-1 border-b border-[color:var(--st-glass-border)] bg-[color:var(--st-accent-dim)] mt-1 shrink-0">
        <span className="text-sm">&#128172;</span>
        <span className="text-[color:var(--st-text-primary)] text-xs font-semibold">Chat</span>
        <span className={cn('w-1.5 h-1.5 rounded-full', statusColorClass[connectionStatus])} />
        <span className="text-[color:var(--st-text-muted)] text-[11px]">
          {connectionStatus === 'connected' ? 'Connected' : connectionStatus}
        </span>

        <div className="flex-1" />

        {/* Own presence dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowPresenceMenu(!showPresenceMenu)}
            className="bg-transparent border border-[color:var(--st-glass-border)] rounded px-2 py-0.5 text-[color:var(--st-text-muted)] text-[11px] cursor-pointer flex items-center gap-1 hover:border-[color:var(--st-accent-glow)] transition-colors"
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', presenceColorClass[ownPresence])} />
            {ownPresence}
          </button>
          {showPresenceMenu && (
            <div className="absolute top-full right-0 mt-0.5 bg-[color:var(--st-bg-elevated)] border border-[color:var(--st-glass-border)] rounded-md overflow-hidden z-[100] min-w-[100px]">
              {(['online', 'busy', 'offline'] as PresenceStatus[]).map(s => (
                <div
                  key={s}
                  onClick={() => handlePresenceChange(s)}
                  className={cn(
                    'px-2.5 py-1.5 flex items-center gap-1.5 cursor-pointer text-[11px] text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-accent-dim)] transition-colors',
                    ownPresence === s && 'bg-blue-500/15',
                  )}
                >
                  <span className={cn('w-1.5 h-1.5 rounded-full', presenceColorClass[s])} />
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </div>
              ))}
            </div>
          )}
        </div>

        {identity && (
          <span
            className="text-blue-400 text-[11px] font-mono cursor-pointer px-1.5 py-px rounded bg-blue-500/10 border border-blue-500/20 hover:bg-blue-500/20 transition-colors"
            title={`Click to copy your full Session ID:\n${identity.sessionId}`}
            onClick={() => {
              window.shieldtier.clipboard.writeText(identity.sessionId);
              const el = document.getElementById('chat-copy-feedback');
              if (el) { el.style.opacity = '1'; setTimeout(() => { el.style.opacity = '0'; }, 1500); }
            }}
          >
            {identity.sessionId.slice(0, 10)}... [copy]
            <span
              id="chat-copy-feedback"
              className="ml-1 text-green-400 text-[9px] opacity-0 transition-opacity duration-300"
            >
              Copied!
            </span>
          </span>
        )}

        <button
          onClick={onToggleCollapse}
          className="bg-transparent border-none text-[color:var(--st-text-muted)] cursor-pointer text-sm px-1 hover:text-[color:var(--st-text-primary)] transition-colors"
          title="Collapse chat"
        >
          &#x2014;
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 flex overflow-hidden">
        <ChatContactList
          contacts={contacts}
          requests={messageRequests}
          selectedContactId={selectedContactId || undefined}
          onSelectContact={(id) => setSelectedContactId(id)}
          onAddContact={handleAddContact}
          onApproveContact={handleApproveContact}
          onRejectContact={handleRejectContact}
        />

        <div className="flex-1 flex flex-col overflow-hidden">
          {selectedContactId && selectedContact ? (
            <ChatConversation
              contactName={selectedContact.displayName}
              contactSessionId={selectedContact.sessionId}
              contactPresence={selectedContact.presence}
              contactLastSeen={selectedContact.lastSeen}
              messages={messages}
              ownSessionId={identity?.sessionId || ''}
              onSend={handleSend}
              onBack={() => setSelectedContactId(null)}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center text-[color:var(--st-text-secondary)] text-[13px]">
              Select a contact to start chatting
            </div>
          )}
        </div>
      </div>

      {/* Onboarding modal */}
      {showOnboarding && identity && (
        <div className="absolute inset-0 bg-[color:var(--st-bg-overlay)] flex items-center justify-center z-[200]">
          <div className="bg-[color:var(--st-bg-elevated)] rounded-xl p-6 max-w-[440px] w-[90%] border border-[color:var(--st-glass-border)]">
            <h3 className="text-[color:var(--st-text-primary)] text-base m-0 mb-3">
              Your Session Identity
            </h3>
            <p className="text-[color:var(--st-text-muted)] text-xs m-0 mb-3 leading-relaxed">
              A Session identity was created for you. Share your Session ID with other
              ShieldTier users to communicate securely with end-to-end encryption.
            </p>
            <div className="mb-3">
              <label className="text-[color:var(--st-text-muted)] text-[11px] block mb-1">
                SESSION ID
              </label>
              <div
                className="bg-[color:var(--st-accent-dim)] rounded-md px-2.5 py-2 font-mono text-[11px] text-blue-400 break-all cursor-pointer hover:bg-blue-500/20 transition-colors"
                onClick={() => window.shieldtier.clipboard.writeText(identity.sessionId)}
                title="Click to copy"
              >
                {identity.sessionId}
              </div>
            </div>
            <div className="mb-4">
              <label className="text-[color:var(--st-text-muted)] text-[11px] block mb-1">
                RECOVERY PHRASE (save securely)
              </label>
              <div className="bg-[color:var(--st-accent-dim)] rounded-md px-2.5 py-2 font-mono text-[11px] text-yellow-400 break-all">
                {identity.mnemonic}
              </div>
            </div>
            <button
              onClick={acknowledgeOnboarding}
              className="w-full py-2.5 rounded-lg border-none bg-st-accent text-white text-[13px] font-semibold cursor-pointer hover:bg-[color:var(--st-accent-hover)] transition-colors"
            >
              I've saved my recovery phrase
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
