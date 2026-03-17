import React, { useEffect, useRef } from 'react';
import type { ChatMessage, PresenceStatus } from '../types';
import ChatMessageInput from './ChatMessageInput';

interface ChatConversationProps {
  contactName: string;
  contactSessionId: string;
  contactPresence: PresenceStatus;
  contactLastSeen?: number;
  messages: ChatMessage[];
  ownSessionId: string;
  onSend: (body: string) => void;
  onBack: () => void;
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDateSeparator(ts: number): string {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatLastSeen(lastSeen?: number): string {
  if (!lastSeen) return '';
  const diff = Date.now() - lastSeen;
  if (diff < 60_000) return 'last seen just now';
  if (diff < 3_600_000) return `last seen ${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `last seen ${Math.floor(diff / 3_600_000)}h ago`;
  return `last seen ${new Date(lastSeen).toLocaleDateString()}`;
}

const presenceDotColor: Record<PresenceStatus, string> = {
  online: '#22c55e',
  busy: '#eab308',
  offline: '#6b7280',
};

const presenceLabel: Record<PresenceStatus, string> = {
  online: 'Online',
  busy: 'Busy',
  offline: 'Offline',
};

export default function ChatConversation({
  contactName, contactSessionId, contactPresence, contactLastSeen,
  messages, ownSessionId, onSend, onBack,
}: ChatConversationProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages.length]);

  // Group messages by date for separators
  let lastDate = '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Conversation header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '6px 12px',
        borderBottom: '1px solid var(--st-border-subtle)',
        backgroundColor: 'var(--st-accent-dim)',
        flexShrink: 0,
      }}>
        <button
          onClick={onBack}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--st-text-muted)',
            cursor: 'pointer',
            fontSize: 16,
            padding: '2px 4px',
          }}
          title="Back to contacts"
        >
          &#x2190;
        </button>
        <span style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          backgroundColor: presenceDotColor[contactPresence],
          flexShrink: 0,
        }} />
        <span style={{ color: 'var(--st-text-primary)', fontSize: 13, fontWeight: 600 }}>
          {contactName}
        </span>
        <span style={{ color: 'var(--st-text-muted)', fontSize: 11 }}>
          {presenceLabel[contactPresence]}
          {contactPresence === 'offline' && contactLastSeen
            ? ` \u00b7 ${formatLastSeen(contactLastSeen)}`
            : ''}
        </span>
      </div>

      {/* Messages */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '8px 12px',
        }}
      >
        {messages.length === 0 && (
          <div style={{
            textAlign: 'center',
            color: 'var(--st-text-muted)',
            fontSize: 12,
            marginTop: 40,
          }}>
            No messages yet. Say hello!
          </div>
        )}
        {messages.map((msg) => {
          const isOwn = msg.senderSessionId === ownSessionId;
          const dateStr = formatDateSeparator(msg.timestamp);
          let showDateSep = false;
          if (dateStr !== lastDate) {
            lastDate = dateStr;
            showDateSep = true;
          }

          return (
            <React.Fragment key={msg.id}>
              {showDateSep && (
                <div style={{
                  textAlign: 'center',
                  color: 'var(--st-text-muted)',
                  fontSize: 10,
                  margin: '12px 0 6px',
                }}>
                  {dateStr}
                </div>
              )}
              <div style={{
                display: 'flex',
                justifyContent: isOwn ? 'flex-end' : 'flex-start',
                marginBottom: 4,
              }}>
                <div style={{
                  maxWidth: '75%',
                  padding: '6px 10px',
                  borderRadius: isOwn ? '12px 12px 4px 12px' : '12px 12px 12px 4px',
                  backgroundColor: isOwn ? '#2563eb' : 'var(--st-accent-dim)',
                  color: 'var(--st-text-primary)',
                  fontSize: 13,
                  lineHeight: '1.4',
                  wordBreak: 'break-word',
                }}>
                  <div style={{ whiteSpace: 'pre-wrap' }}>{msg.body}</div>
                  <div style={{
                    fontSize: 10,
                    color: isOwn ? 'rgba(255,255,255,0.5)' : 'var(--st-text-muted)',
                    marginTop: 2,
                    textAlign: 'right',
                  }}>
                    {formatTime(msg.timestamp)}
                    {isOwn && msg.status === 'sending' && ' ...'}
                    {isOwn && msg.status === 'failed' && ' \u2717'}
                  </div>
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>

      {/* Input */}
      <ChatMessageInput onSend={onSend} />
    </div>
  );
}
