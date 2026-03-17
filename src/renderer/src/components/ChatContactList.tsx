import React, { useState } from 'react';
import type { ChatContact, PresenceStatus, ContactLookupResult } from '../types';

type Tab = 'contacts' | 'requests';

interface ChatContactListProps {
  contacts: ChatContact[];
  requests: ChatContact[];
  selectedContactId?: string;
  onSelectContact: (sessionId: string) => void;
  onAddContact: (sessionId: string, displayName: string) => void;
  onApproveContact: (sessionId: string) => void;
  onRejectContact: (sessionId: string) => void;
}

const presenceDotColor: Record<PresenceStatus, string> = {
  online: '#22c55e',
  busy: '#eab308',
  offline: '#6b7280',
};

export default function ChatContactList({
  contacts, requests, selectedContactId, onSelectContact, onAddContact,
  onApproveContact, onRejectContact,
}: ChatContactListProps) {
  const [tab, setTab] = useState<Tab>('contacts');
  const [showAdd, setShowAdd] = useState(false);
  const [newSessionId, setNewSessionId] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [addError, setAddError] = useState('');
  const [lookupResult, setLookupResult] = useState<ContactLookupResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  const handleLookup = async () => {
    const id = newSessionId.trim();
    if (!id || !id.startsWith('05') || id.length !== 66) return;
    setLookupLoading(true);
    setLookupResult(null);
    try {
      const result = await window.shieldtier.chat.lookupUser(id);
      setLookupResult(result);
      if (result && !newDisplayName.trim()) {
        setNewDisplayName(result.analystName);
      }
    } catch {
      setLookupResult(null);
    } finally {
      setLookupLoading(false);
    }
  };

  const handleAdd = async () => {
    setAddError('');
    const id = newSessionId.trim();
    if (!id) {
      setAddError('Session ID required');
      return;
    }
    if (!id.startsWith('05') || id.length !== 66) {
      setAddError('Must be full 66-char Session ID starting with "05".');
      return;
    }
    try {
      await onAddContact(id, newDisplayName.trim());
      setNewSessionId('');
      setNewDisplayName('');
      setShowAdd(false);
      setLookupResult(null);
    } catch (err: any) {
      setAddError(err.message || 'Failed to add contact');
    }
  };

  // Sort: online first, then busy, then offline; then by name
  const sorted = [...contacts].sort((a, b) => {
    const order: Record<string, number> = { online: 0, busy: 1, offline: 2 };
    const diff = (order[a.presence] ?? 2) - (order[b.presence] ?? 2);
    if (diff !== 0) return diff;
    return a.displayName.localeCompare(b.displayName);
  });

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      width: 200,
      minWidth: 200,
      borderRight: '1px solid var(--st-border-subtle)',
    }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex',
        borderBottom: '1px solid var(--st-border-subtle)',
        flexShrink: 0,
      }}>
        <button
          onClick={() => setTab('contacts')}
          style={{
            flex: 1,
            padding: '6px 0',
            background: 'none',
            border: 'none',
            borderBottom: tab === 'contacts' ? '2px solid #3b82f6' : '2px solid transparent',
            color: tab === 'contacts' ? 'var(--st-text-primary)' : 'var(--st-text-muted)',
            fontSize: 11,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Contacts
        </button>
        <button
          onClick={() => setTab('requests')}
          style={{
            flex: 1,
            padding: '6px 0',
            background: 'none',
            border: 'none',
            borderBottom: tab === 'requests' ? '2px solid #3b82f6' : '2px solid transparent',
            color: tab === 'requests' ? 'var(--st-text-primary)' : 'var(--st-text-muted)',
            fontSize: 11,
            fontWeight: 600,
            cursor: 'pointer',
            position: 'relative',
          }}
        >
          Requests
          {requests.length > 0 && (
            <span style={{
              position: 'absolute',
              top: 2,
              right: 8,
              backgroundColor: '#ef4444',
              color: '#fff',
              fontSize: 9,
              fontWeight: 700,
              borderRadius: 10,
              padding: '0 5px',
              minWidth: 14,
              textAlign: 'center',
              lineHeight: '16px',
            }}>
              {requests.length}
            </span>
          )}
        </button>
      </div>

      {/* Contacts tab */}
      {tab === 'contacts' && (
        <>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {sorted.length === 0 && !showAdd && (
              <div style={{
                padding: 12,
                color: 'var(--st-text-muted)',
                fontSize: 11,
                textAlign: 'center',
              }}>
                No contacts yet
              </div>
            )}
            {sorted.map(contact => (
              <div
                key={contact.sessionId}
                onClick={() => onSelectContact(contact.sessionId)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '8px 12px',
                  cursor: 'pointer',
                  backgroundColor: selectedContactId === contact.sessionId
                    ? 'rgba(59, 130, 246, 0.15)'
                    : 'transparent',
                  borderLeft: selectedContactId === contact.sessionId
                    ? '2px solid #3b82f6'
                    : '2px solid transparent',
                  transition: 'background-color 0.15s',
                }}
                onMouseEnter={e => {
                  if (selectedContactId !== contact.sessionId)
                    (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--st-accent-dim)';
                }}
                onMouseLeave={e => {
                  if (selectedContactId !== contact.sessionId)
                    (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent';
                }}
              >
                <span style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  backgroundColor: presenceDotColor[contact.presence],
                  flexShrink: 0,
                }} />
                <span style={{
                  flex: 1,
                  color: 'var(--st-text-primary)',
                  fontSize: 12,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {contact.displayName}
                </span>
                {contact.unreadCount > 0 && (
                  <span style={{
                    backgroundColor: '#3b82f6',
                    color: '#fff',
                    fontSize: 10,
                    fontWeight: 700,
                    borderRadius: 10,
                    padding: '1px 6px',
                    minWidth: 18,
                    textAlign: 'center',
                  }}>
                    {contact.unreadCount}
                  </span>
                )}
              </div>
            ))}
          </div>

          {/* Add contact form */}
          {showAdd ? (
            <div style={{
              padding: 8,
              borderTop: '1px solid var(--st-border-subtle)',
              backgroundColor: 'var(--st-accent-dim)',
            }}>
              <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                <input
                  type="text"
                  placeholder="Session ID (05...)"
                  value={newSessionId}
                  onChange={e => { setNewSessionId(e.target.value); setLookupResult(null); }}
                  style={{
                    flex: 1,
                    background: 'var(--st-accent-dim)',
                    border: '1px solid var(--st-glass-border)',
                    borderRadius: 4,
                    padding: '4px 6px',
                    color: 'var(--st-text-primary)',
                    fontSize: 11,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
                <button
                  onClick={handleLookup}
                  disabled={lookupLoading || newSessionId.trim().length !== 66}
                  style={{
                    padding: '4px 8px',
                    borderRadius: 4,
                    border: 'none',
                    background: 'rgba(59,130,246,0.2)',
                    color: '#3b82f6',
                    fontSize: 10,
                    cursor: 'pointer',
                    opacity: (lookupLoading || newSessionId.trim().length !== 66) ? 0.4 : 1,
                  }}
                  title="Look up user on server"
                >
                  {lookupLoading ? '...' : 'Lookup'}
                </button>
              </div>
              {lookupResult && (
                <div style={{
                  fontSize: 10,
                  color: '#22c55e',
                  marginBottom: 4,
                  padding: '3px 6px',
                  backgroundColor: 'rgba(34,197,94,0.08)',
                  borderRadius: 4,
                  border: '1px solid rgba(34,197,94,0.2)',
                }}>
                  Found: {lookupResult.analystName}
                </div>
              )}
              <input
                type="text"
                placeholder="Display name"
                value={newDisplayName}
                onChange={e => setNewDisplayName(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--st-accent-dim)',
                  border: '1px solid var(--st-glass-border)',
                  borderRadius: 4,
                  padding: '4px 6px',
                  color: 'var(--st-text-primary)',
                  fontSize: 11,
                  marginBottom: 4,
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
              {addError && (
                <div style={{ color: '#ef4444', fontSize: 10, marginBottom: 4 }}>{addError}</div>
              )}
              <div style={{ display: 'flex', gap: 4 }}>
                <button
                  onClick={handleAdd}
                  style={{
                    flex: 1,
                    padding: '4px 0',
                    borderRadius: 4,
                    border: 'none',
                    background: '#3b82f6',
                    color: '#fff',
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Add
                </button>
                <button
                  onClick={() => { setShowAdd(false); setAddError(''); setLookupResult(null); }}
                  style={{
                    padding: '4px 8px',
                    borderRadius: 4,
                    border: 'none',
                    background: 'var(--st-border-subtle)',
                    color: 'var(--st-text-muted)',
                    fontSize: 11,
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setShowAdd(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 4,
                padding: '8px 12px',
                borderTop: '1px solid var(--st-border-subtle)',
                background: 'none',
                border: 'none',
                color: '#3b82f6',
                fontSize: 12,
                cursor: 'pointer',
                width: '100%',
              }}
            >
              + Add Contact
            </button>
          )}
        </>
      )}

      {/* Requests tab */}
      {tab === 'requests' && (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {requests.length === 0 ? (
            <div style={{
              padding: 16,
              color: 'var(--st-text-muted)',
              fontSize: 11,
              textAlign: 'center',
            }}>
              No pending requests
            </div>
          ) : (
            requests.map(req => (
              <div
                key={req.sessionId}
                style={{
                  padding: '10px 12px',
                  borderBottom: '1px solid var(--st-border-subtle)',
                }}
              >
                <div style={{
                  color: 'var(--st-text-primary)',
                  fontSize: 12,
                  fontWeight: 500,
                  marginBottom: 2,
                }}>
                  {req.displayName || 'Unknown'}
                </div>
                <div style={{
                  color: 'var(--st-text-muted)',
                  fontSize: 10,
                  fontFamily: 'monospace',
                  marginBottom: 6,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {req.sessionId.slice(0, 16)}...
                </div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button
                    onClick={() => onApproveContact(req.sessionId)}
                    style={{
                      flex: 1,
                      padding: '4px 0',
                      borderRadius: 4,
                      border: 'none',
                      background: '#22c55e',
                      color: '#fff',
                      fontSize: 10,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Accept
                  </button>
                  <button
                    onClick={() => onRejectContact(req.sessionId)}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: 'none',
                      background: 'rgba(239,68,68,0.15)',
                      color: '#ef4444',
                      fontSize: 10,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
