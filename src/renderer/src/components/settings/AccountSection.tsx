import React, { useState } from 'react';
import type { AuthUser } from '../../types';
import { cn } from '../../lib/utils';

export interface AccountSectionProps {
  user: AuthUser;
  avatar: string;
  onAvatarChange: (avatar: string) => void;
  onUserUpdated: (user: AuthUser) => void;
  onLogout: () => void;
}

const AVATARS = [
  { key: 'shield', emoji: '\u{1F6E1}', label: 'Shield' },
  { key: 'detective', emoji: '\u{1F575}', label: 'Detective' },
  { key: 'robot', emoji: '\u{1F916}', label: 'Robot' },
  { key: 'skull', emoji: '\u{1F480}', label: 'Skull' },
  { key: 'ghost', emoji: '\u{1F47B}', label: 'Ghost' },
  { key: 'alien', emoji: '\u{1F47E}', label: 'Alien' },
  { key: 'ninja', emoji: '\u{1F977}', label: 'Ninja' },
  { key: 'astronaut', emoji: '\u{1F468}\u{200D}\u{1F680}', label: 'Astronaut' },
];

const inputClass = 'w-full h-9 bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-xl px-3 text-[13px] text-[color:var(--st-text-primary)] placeholder:text-[color:var(--st-text-muted)] outline-none focus:border-[color:var(--st-accent)] focus:shadow-[0_0_0_3px_var(--st-accent-glow)] transition-all duration-200';

function resolveAvatar(val: string): string {
  const found = AVATARS.find(a => a.key === val || a.emoji === val);
  return found?.emoji || AVATARS[0].emoji;
}

export function AccountSection({ user, avatar, onAvatarChange, onUserUpdated, onLogout }: AccountSectionProps) {
  // Profile
  const [analystName, setAnalystName] = useState(user.analystName);
  const [selectedAvatar, setSelectedAvatar] = useState(() => resolveAvatar(avatar));
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [resending, setResending] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Password
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const isDirty = analystName !== user.analystName || selectedAvatar !== resolveAvatar(avatar);
  const pwReady = currentPw && newPw && confirmPw && newPw === confirmPw && newPw.length >= 8;

  const handleSave = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const result = await window.shieldtier.auth.updateProfile({ analystName, avatar: selectedAvatar });
      if (result.success && result.user) {
        onAvatarChange(selectedAvatar);
        onUserUpdated(result.user);
        setMsg({ type: 'success', text: 'Saved' });
        setTimeout(() => setMsg(null), 2000);
      } else {
        setMsg({ type: 'error', text: result.error || 'Failed to save.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err.message || 'Failed to save.' });
    }
    setSaving(false);
  };

  const handleResend = async () => {
    setResending(true);
    setVerifyMsg(null);
    try {
      const result = await window.shieldtier.auth.resendVerification();
      setVerifyMsg(result.success ? (result.message || 'Verification email sent.') : (result.error || 'Failed.'));
    } catch (err: any) {
      setVerifyMsg(err.message || 'Failed.');
    }
    setResending(false);
  };

  const handleCopy = async (field: string, value: string) => {
    try {
      await window.shieldtier.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 1500);
    } catch { /* ignore */ }
  };

  const handleChangePassword = async () => {
    setPwMsg(null);
    if (newPw !== confirmPw) { setPwMsg({ type: 'error', text: 'Passwords do not match.' }); return; }
    if (newPw.length < 8) { setPwMsg({ type: 'error', text: 'Minimum 8 characters.' }); return; }
    setPwSaving(true);
    try {
      const result = await window.shieldtier.auth.changePassword(currentPw, newPw);
      if (result.success) {
        setPwMsg({ type: 'success', text: 'Password changed.' });
        setCurrentPw(''); setNewPw(''); setConfirmPw('');
        setTimeout(() => setPwMsg(null), 3000);
      } else {
        setPwMsg({ type: 'error', text: result.error || 'Failed.' });
      }
    } catch (err: any) {
      setPwMsg({ type: 'error', text: err.message || 'Failed.' });
    }
    setPwSaving(false);
  };

  const truncateId = (v: string) => v.length > 24 ? v.slice(0, 12) + '\u2026' + v.slice(-8) : v;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-[15px] font-semibold text-[color:var(--st-text-primary)]">Account</h2>
        <p className="text-[11px] text-[color:var(--st-text-muted)] mt-0.5">Your identity, password, and account details.</p>
      </div>

      {/* ── Unified surface ── */}
      <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] overflow-hidden">

        {/* ── Hero: centered avatar + identity ── */}
        <div className="flex flex-col items-center pt-8 pb-6 px-6">
          <div className="relative mb-4">
            <div
              className="w-[72px] h-[72px] rounded-[22px] bg-[color:var(--st-bg-base)] border-2 border-[color:var(--st-accent)]/40 flex items-center justify-center transition-all duration-300"
              style={{ boxShadow: '0 0 24px var(--st-accent-glow), 0 0 48px rgba(10, 132, 255, 0.06)' }}
            >
              <span className="text-4xl select-none">{selectedAvatar}</span>
            </div>
            <div className="absolute -bottom-0.5 -right-0.5 w-4 h-4 rounded-full bg-[color:var(--st-success)] border-[3px] border-[color:var(--st-bg-elevated)]" />
          </div>
          <h3 className="text-[17px] font-semibold text-[color:var(--st-text-primary)] tracking-tight">{user.analystName}</h3>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[12px] text-[color:var(--st-text-muted)]">{user.email}</span>
            {user.emailVerified ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-px rounded-full bg-[color:var(--st-success)]/10 border border-[color:var(--st-success)]/20">
                <svg width="10" height="10" viewBox="0 0 16 16" fill="none"><path d="M3 8.5L6.5 12L13 4" stroke="var(--st-success)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                <span className="text-[9px] text-[color:var(--st-success)] font-medium">Verified</span>
              </span>
            ) : (
              <button onClick={handleResend} disabled={resending} className="inline-flex items-center gap-1 px-1.5 py-px rounded-full bg-[color:var(--st-warning)]/10 border border-[color:var(--st-warning)]/20 hover:bg-[color:var(--st-warning)]/15 transition-colors cursor-pointer">
                <span className="text-[9px] text-[color:var(--st-warning)] font-medium">{resending ? 'Sending\u2026' : 'Verify email'}</span>
              </button>
            )}
          </div>
          {verifyMsg && <p className="text-[10px] text-[color:var(--st-warning)] mt-1.5">{verifyMsg}</p>}
        </div>

        <div className="mx-6 h-px bg-[color:var(--st-border)]" />

        {/* ── Avatar picker ── */}
        <div className="px-6 py-5">
          <label className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider block mb-3">Avatar</label>
          <div className="flex items-center justify-center gap-2" role="radiogroup" aria-label="Choose avatar">
            {AVATARS.map((opt) => {
              const selected = selectedAvatar === opt.emoji;
              return (
                <button key={opt.label} type="button" role="radio" aria-checked={selected} aria-label={opt.label} title={opt.label} onClick={() => setSelectedAvatar(opt.emoji)}
                  className={cn('w-11 h-11 rounded-2xl flex items-center justify-center transition-all duration-200 cursor-pointer',
                    selected ? 'bg-[color:var(--st-accent-dim)] ring-2 ring-[color:var(--st-accent)] shadow-[0_0_12px_var(--st-accent-glow)] scale-110' : 'bg-[color:var(--st-bg-base)] hover:bg-[color:var(--st-bg-panel)] hover:scale-105'
                  )}>
                  <span className={cn('text-xl transition-all duration-200', selected && 'text-2xl')}>{opt.emoji}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="mx-6 h-px bg-[color:var(--st-border)]" />

        {/* ── Analyst Name ── */}
        <div className="px-6 py-5">
          <label htmlFor="analyst-name" className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider block mb-2">Analyst Name</label>
          <input id="analyst-name" type="text" value={analystName} onChange={(e) => setAnalystName(e.target.value)} placeholder="Your analyst name" className={inputClass} />
        </div>

        {/* ── Save profile footer ── */}
        <div className="px-6 py-4 border-t border-[color:var(--st-border)] flex items-center justify-between" style={{ background: 'var(--st-bg-panel)' }}>
          <div className="flex items-center gap-2">
            {isDirty && !msg && (
              <span className="flex items-center gap-1.5 text-[10px] text-[color:var(--st-text-muted)]">
                <span className="w-1.5 h-1.5 rounded-full bg-[color:var(--st-warning)] animate-pulse" />
                Unsaved changes
              </span>
            )}
            {msg && (
              <span className={cn('flex items-center gap-1.5 text-[11px] font-medium', msg.type === 'success' ? 'text-[color:var(--st-success)]' : 'text-[color:var(--st-danger)]')}>
                {msg.type === 'success' && <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M3 8.5L6.5 12L13 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>}
                {msg.text}
              </span>
            )}
          </div>
          <button type="button" onClick={handleSave} disabled={saving || !isDirty}
            className={cn('h-8 px-4 rounded-xl text-[12px] font-medium transition-all duration-200 cursor-pointer',
              isDirty ? 'bg-[color:var(--st-accent)] text-white hover:brightness-110 shadow-[0_0_16px_var(--st-accent-glow)]' : 'bg-[color:var(--st-bg-base)] text-[color:var(--st-text-muted)] border border-[color:var(--st-border)] opacity-50 cursor-not-allowed'
            )}>
            {saving ? 'Saving\u2026' : 'Save Changes'}
          </button>
        </div>
      </div>

      {/* ── Password surface ── */}
      <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] overflow-hidden">
        <div className="px-6 py-5 space-y-4">
          <div className="flex items-center gap-3">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] shrink-0">
              <rect x="3" y="7" width="10" height="7" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
              <path d="M5 7V5a3 3 0 016 0v2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
            </svg>
            <label className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">Change Password</label>
          </div>

          <div className="space-y-3">
            <div>
              <label htmlFor="current-pw" className="text-[11px] text-[color:var(--st-text-muted)] block mb-1">Current Password</label>
              <input id="current-pw" type="password" value={currentPw} onChange={e => setCurrentPw(e.target.value)} placeholder="Enter current password" className={inputClass} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="new-pw" className="text-[11px] text-[color:var(--st-text-muted)] block mb-1">New Password</label>
                <input id="new-pw" type="password" value={newPw} onChange={e => setNewPw(e.target.value)} placeholder="Min. 8 characters" className={inputClass} />
              </div>
              <div>
                <label htmlFor="confirm-pw" className="text-[11px] text-[color:var(--st-text-muted)] block mb-1">Confirm Password</label>
                <input id="confirm-pw" type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} placeholder="Re-enter password" className={inputClass} />
              </div>
            </div>
            {newPw.length > 0 && newPw.length < 8 && (
              <p className="text-[10px] text-[color:var(--st-warning)]">{8 - newPw.length} more character{8 - newPw.length !== 1 ? 's' : ''} needed</p>
            )}
            {confirmPw.length > 0 && newPw !== confirmPw && (
              <p className="text-[10px] text-[color:var(--st-danger)]">Passwords do not match</p>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button type="button" onClick={handleChangePassword} disabled={pwSaving || !pwReady}
              className={cn('h-8 px-4 rounded-xl text-[12px] font-medium transition-all duration-200 cursor-pointer',
                pwReady ? 'bg-[color:var(--st-accent)] text-white hover:brightness-110 shadow-[0_0_12px_var(--st-accent-glow)]' : 'bg-[color:var(--st-bg-base)] text-[color:var(--st-text-muted)] border border-[color:var(--st-border)] opacity-50 cursor-not-allowed'
              )}>
              {pwSaving ? 'Changing\u2026' : 'Update Password'}
            </button>
            {pwMsg && (
              <span className={cn('text-[11px]', pwMsg.type === 'success' ? 'text-[color:var(--st-success)]' : 'text-[color:var(--st-danger)]')}>{pwMsg.text}</span>
            )}
          </div>
        </div>
      </div>

      {/* ── Identifiers + Sign Out surface ── */}
      <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] overflow-hidden">
        {/* IDs */}
        <div className="px-6 py-5 space-y-3">
          <label className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider block">Identifiers</label>
          <IdRow label="User ID" value={user.id} display={truncateId(user.id)} copied={copiedField === 'userId'} onCopy={() => handleCopy('userId', user.id)} />
          {user.chatSessionId && (
            <IdRow label="Chat Session" value={user.chatSessionId} display={truncateId(user.chatSessionId)} copied={copiedField === 'chatId'} onCopy={() => handleCopy('chatId', user.chatSessionId!)} />
          )}
        </div>

        <div className="mx-6 h-px bg-[color:var(--st-border)]" />

        {/* Sign Out */}
        <div className="px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] shrink-0">
                <path d="M6 2H4a2 2 0 00-2 2v8a2 2 0 002 2h2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                <path d="M10 11l3-3-3-3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M13 8H6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
              </svg>
              <div>
                <span className="text-[12px] font-medium text-[color:var(--st-text-primary)]">Sign Out</span>
                <p className="text-[10px] text-[color:var(--st-text-muted)]">Local data preserved. You'll need to log in again.</p>
              </div>
            </div>
            <button type="button" onClick={onLogout}
              className="h-8 px-4 rounded-xl text-[12px] font-medium text-[color:var(--st-danger)] border border-[color:var(--st-danger)]/30 hover:bg-[color:var(--st-danger-dim)] transition-all duration-200 cursor-pointer shrink-0">
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function IdRow({ label, display, copied, onCopy }: { label: string; value: string; display: string; copied: boolean; onCopy: () => void }) {
  return (
    <div className="flex items-center justify-between group">
      <span className="text-[11px] text-[color:var(--st-text-muted)] w-24 shrink-0">{label}</span>
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-[12px] text-[color:var(--st-text-secondary)] font-mono truncate">{display}</span>
        <button type="button" onClick={onCopy} title="Copy"
          className={cn('w-6 h-6 rounded-lg flex items-center justify-center transition-all duration-200 cursor-pointer shrink-0',
            copied ? 'bg-[color:var(--st-success)]/10 text-[color:var(--st-success)]' : 'text-[color:var(--st-text-muted)] opacity-0 group-hover:opacity-100 hover:bg-[color:var(--st-border-subtle)] hover:text-[color:var(--st-text-secondary)]'
          )}>
          {copied ? (
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M3 8.5L6.5 12L13 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
          ) : (
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="8" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.2" /><path d="M3 11V3a1.5 1.5 0 011.5-1.5H11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></svg>
          )}
        </button>
      </div>
    </div>
  );
}
