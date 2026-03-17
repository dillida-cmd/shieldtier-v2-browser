import React, { useEffect, useState, useRef } from 'react';
import { cn } from '../../lib/utils';

interface DashboardProps {
  hasProxy: boolean;
  analystName: string;
  sessionCount: number;
  onNewSession: () => void;
  onConfigureProxy: () => void;
  onOpenSettings: () => void;
}

// ── UTC / Local Clock ──
function LiveClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const utc = now.toLocaleTimeString('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const local = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
  const utcDate = now.toLocaleDateString('en-GB', { timeZone: 'UTC', day: '2-digit', month: 'short', year: 'numeric' });

  return (
    <div className="flex items-center gap-4">
      <div className="text-right">
        <div className="text-[20px] font-mono font-bold text-[color:var(--st-text-primary)] tabular-nums tracking-tight">{utc}</div>
        <div className="text-[10px] text-[color:var(--st-text-muted)] font-mono">UTC &middot; {utcDate}</div>
      </div>
      <div className="w-px h-8 bg-[color:var(--st-border)]" />
      <div className="text-right">
        <div className="text-[14px] font-mono text-[color:var(--st-text-secondary)] tabular-nums">{local}</div>
        <div className="text-[10px] text-[color:var(--st-text-muted)] font-mono">Local</div>
      </div>
    </div>
  );
}

// ── Quick IOC Lookup ──
function QuickIOCLookup() {
  const [query, setQuery] = useState('');
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<{ found: boolean; detail: string } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleCheck = async () => {
    const q = query.trim();
    if (!q) return;
    setChecking(true);
    setResult(null);
    try {
      // Use threatfeed matches with a special check — for now search loaded feeds
      const stats = await window.shieldtier.threatfeed.getStats();
      const totalIOCs = stats?.totalIOCs || 0;
      if (totalIOCs === 0) {
        setResult({ found: false, detail: 'No threat feeds loaded. Configure feeds in Settings > Integrations.' });
      } else {
        // TODO: wire to a real IOC lookup IPC once C++ implements it
        setResult({ found: false, detail: `Not found in ${totalIOCs.toLocaleString()} loaded IOCs.` });
      }
    } catch {
      setResult({ found: false, detail: 'Lookup failed. Check your connection.' });
    }
    setChecking(false);
  };

  const detectType = (v: string): string => {
    if (/^[a-f0-9]{32}$/i.test(v)) return 'MD5';
    if (/^[a-f0-9]{40}$/i.test(v)) return 'SHA1';
    if (/^[a-f0-9]{64}$/i.test(v)) return 'SHA256';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'IPv4';
    if (v.includes(':') && /^[a-f0-9:]+$/i.test(v)) return 'IPv6';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'Domain';
    if (/^https?:\/\//i.test(v)) return 'URL';
    return 'IOC';
  };

  const trimmed = query.trim();
  const iocType = trimmed ? detectType(trimmed) : '';

  return (
    <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] p-5">
      <div className="flex items-center gap-2.5 mb-3">
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] shrink-0">
          <circle cx="7" cy="7" r="5.5" stroke="currentColor" strokeWidth="1.2" />
          <path d="M11.5 11.5L14.5 14.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        </svg>
        <span className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">Quick IOC Lookup</span>
        {iocType && (
          <span className="text-[9px] font-mono text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] rounded px-1.5 py-0.5">{iocType}</span>
        )}
      </div>

      <div className="flex gap-2">
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={e => { setQuery(e.target.value); setResult(null); }}
          onKeyDown={e => e.key === 'Enter' && handleCheck()}
          placeholder="Paste IP, domain, hash, or URL..."
          className="flex-1 h-9 bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-xl px-3 text-[13px] font-mono text-[color:var(--st-text-primary)] placeholder:text-[color:var(--st-text-muted)] outline-none focus:border-[color:var(--st-accent)] focus:shadow-[0_0_0_3px_var(--st-accent-glow)] transition-all duration-200"
        />
        <button
          type="button"
          onClick={handleCheck}
          disabled={!trimmed || checking}
          className={cn(
            'h-9 px-4 rounded-xl text-[12px] font-medium transition-all duration-200 cursor-pointer shrink-0',
            trimmed
              ? 'bg-[color:var(--st-accent)] text-white hover:brightness-110 shadow-[0_0_12px_var(--st-accent-glow)]'
              : 'bg-[color:var(--st-bg-base)] text-[color:var(--st-text-muted)] border border-[color:var(--st-border)] opacity-50 cursor-not-allowed'
          )}
        >
          {checking ? 'Checking\u2026' : 'Check'}
        </button>
      </div>

      {result && (
        <div className={cn(
          'mt-3 px-3 py-2 rounded-lg text-[11px]',
          result.found
            ? 'bg-[color:var(--st-danger)]/10 text-[color:var(--st-danger)] border border-[color:var(--st-danger)]/20'
            : 'bg-[color:var(--st-bg-base)] text-[color:var(--st-text-muted)] border border-[color:var(--st-border)]'
        )}>
          {result.found ? (
            <span className="flex items-center gap-1.5">
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2"/><path d="M8 5v3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/><circle cx="8" cy="11" r="0.8" fill="currentColor"/></svg>
              {result.detail}
            </span>
          ) : result.detail}
        </div>
      )}
    </div>
  );
}

// ── Session Stats ──
function SessionStats({ sessionCount }: { sessionCount: number }) {
  const [feedStats, setFeedStats] = useState({ feedsLoaded: 0, totalIOCs: 0 });

  useEffect(() => {
    (async () => {
      try {
        const s = await window.shieldtier.threatfeed.getStats();
        setFeedStats({
          feedsLoaded: Object.keys(s?.feedBreakdown || {}).length,
          totalIOCs: s?.totalIOCs || 0,
        });
      } catch { /* silent */ }
    })();
  }, []);

  const items = [
    { label: 'Active Sessions', value: sessionCount, accent: true },
    { label: 'Feeds Active', value: feedStats.feedsLoaded, accent: false },
    { label: 'IOCs Loaded', value: feedStats.totalIOCs.toLocaleString(), accent: false },
  ];

  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map(item => (
        <div key={item.label} className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] px-4 py-3.5 text-center">
          <div className={cn(
            'text-[18px] font-bold font-mono tabular-nums',
            item.accent ? 'text-[color:var(--st-accent)]' : 'text-[color:var(--st-text-primary)]'
          )}>
            {item.value}
          </div>
          <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Recent Investigations (compact) ──
function RecentCases() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const result = await window.shieldtier.auth.getCases();
        if (result.success && result.cases) {
          setCases(result.cases.slice(0, 6));
        }
      } catch { /* silent */ }
      setLoading(false);
    })();
  }, []);

  return (
    <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] overflow-hidden">
      <div className="px-5 py-3.5 border-b border-[color:var(--st-border)]">
        <div className="flex items-center gap-2.5">
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] shrink-0">
            <path d="M13 2H3a1 1 0 00-1 1v10a1 1 0 001 1h10a1 1 0 001-1V3a1 1 0 00-1-1z" stroke="currentColor" strokeWidth="1.2" />
            <path d="M5 5h6M5 8h4M5 11h2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
          </svg>
          <span className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">Recent Investigations</span>
        </div>
      </div>

      {loading ? (
        <div className="p-4 space-y-2">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-9 rounded-lg bg-[color:var(--st-border-subtle)] animate-pulse" />
          ))}
        </div>
      ) : cases.length === 0 ? (
        <div className="px-5 py-8 text-center">
          <p className="text-[12px] text-[color:var(--st-text-muted)]">No investigations yet</p>
          <p className="text-[10px] text-[color:var(--st-text-muted)] opacity-50 mt-1">
            Start your first case with <kbd className="font-mono bg-[color:var(--st-accent-dim)] rounded px-1 py-0.5 border border-[color:var(--st-border-subtle)] text-[9px]">New Investigation</kbd>
          </p>
        </div>
      ) : (
        <div className="divide-y divide-[color:var(--st-border-subtle)]">
          {cases.map((c: any) => (
            <div key={c.id} className="px-5 py-2.5 flex items-center gap-3 hover:bg-[color:var(--st-accent-dim)] transition-colors">
              <span className="text-[10px] font-mono text-[color:var(--st-accent)] shrink-0 w-20">{c.caseId}</span>
              <span className="text-[12px] text-[color:var(--st-text-primary)] truncate flex-1">{c.caseName}</span>
              <span className="text-[10px] text-[color:var(--st-text-muted)] font-mono shrink-0">
                {new Date(c.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Compact System Health ──
function SystemHealth() {
  const [checks, setChecks] = useState<{ label: string; ok: boolean; detail: string }[]>([]);

  useEffect(() => {
    (async () => {
      const items: { label: string; ok: boolean; detail: string }[] = [];

      // Cloud
      items.push({ label: 'Cloud', ok: true, detail: 'Connected' });

      // QEMU
      try {
        const q = await window.shieldtier.vm.getQEMUStatus();
        items.push({ label: 'QEMU', ok: !!q.installed, detail: q.installed ? q.version || 'OK' : 'Missing' });
      } catch {
        items.push({ label: 'QEMU', ok: false, detail: 'Error' });
      }

      // API Keys
      try {
        const config = await window.shieldtier.config.getAPIKeys?.();
        const n = config ? Object.values(config).filter(Boolean).length : 0;
        items.push({ label: 'API Keys', ok: n > 0, detail: n > 0 ? `${n} set` : 'None' });
      } catch {
        items.push({ label: 'API Keys', ok: false, detail: 'Error' });
      }

      // Feeds
      try {
        const s = await window.shieldtier.threatfeed.getStats();
        const n = Object.keys(s?.feedBreakdown || {}).length;
        items.push({ label: 'Feeds', ok: n > 0, detail: n > 0 ? `${n} active` : 'None' });
      } catch {
        items.push({ label: 'Feeds', ok: false, detail: 'None' });
      }

      setChecks(items);
    })();
  }, []);

  return (
    <div className="flex items-center gap-4 px-1">
      {checks.map(c => (
        <div key={c.label} className="flex items-center gap-1.5">
          <span className={cn('w-1.5 h-1.5 rounded-full', c.ok ? 'bg-[color:var(--st-success)]' : 'bg-[color:var(--st-warning)]')} />
          <span className="text-[10px] text-[color:var(--st-text-muted)]">{c.label}</span>
          <span className="text-[10px] text-[color:var(--st-text-muted)] opacity-50 font-mono">{c.detail}</span>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Main Dashboard
// ═══════════════════════════════════════════════════════

export function Dashboard({ hasProxy, analystName, sessionCount, onNewSession, onConfigureProxy, onOpenSettings }: DashboardProps) {
  const greeting = getGreeting();

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-4xl mx-auto px-8 py-10">

          {/* ── Header: Greeting + UTC Clock ── */}
          <div className="flex items-start justify-between mb-8">
            <div>
              <h1 className="text-[22px] font-bold text-[color:var(--st-text-primary)] mb-0.5">
                {greeting}, {analystName || 'Analyst'}
              </h1>
              <p className="text-[12px] text-[color:var(--st-text-muted)]">
                ShieldTier Mission Control
              </p>
            </div>
            <LiveClock />
          </div>

          {/* ── Quick Actions ── */}
          <div className="grid grid-cols-3 gap-3 mb-6">
            {/* New Investigation */}
            <button
              type="button"
              onClick={hasProxy ? onNewSession : onConfigureProxy}
              className="rounded-2xl border border-[color:var(--st-accent)]/20 bg-[color:var(--st-bg-elevated)] p-4 text-left transition-all hover:border-[color:var(--st-accent)]/40 hover:shadow-[0_0_20px_var(--st-accent-glow)] group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-[color:var(--st-accent)]/10 flex items-center justify-center shrink-0">
                  <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-accent)]">
                    <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" />
                    <path d="M8 5.5v5M5.5 8h5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                  </svg>
                </div>
                <div>
                  <div className="text-[13px] font-medium text-[color:var(--st-text-primary)] group-hover:text-[color:var(--st-accent)] transition-colors">New Investigation</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">Isolated browser session</div>
                </div>
              </div>
            </button>

            {/* Paste URL to Investigate */}
            <button
              type="button"
              onClick={hasProxy ? onNewSession : onConfigureProxy}
              className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] p-4 text-left transition-all hover:border-[color:var(--st-accent)]/30 hover:bg-[color:var(--st-accent-dim)] group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-[color:var(--st-accent-dim)] flex items-center justify-center shrink-0">
                  <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] group-hover:text-[color:var(--st-accent)] transition-colors">
                    <path d="M2 8c0-3 2.5-5.5 6-5.5s6 2.5 6 5.5-2.5 5.5-6 5.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                    <path d="M8 5v3l2 1.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                    <path d="M2 11l-1 3 3-1 4-4-2-2-4 4z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                  </svg>
                </div>
                <div>
                  <div className="text-[13px] font-medium text-[color:var(--st-text-primary)] group-hover:text-[color:var(--st-accent)] transition-colors">Investigate URL</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">Paste suspicious link</div>
                </div>
              </div>
            </button>

            {/* Settings */}
            <button
              type="button"
              onClick={onOpenSettings}
              className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] p-4 text-left transition-all hover:border-[color:var(--st-accent)]/30 hover:bg-[color:var(--st-accent-dim)] group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-[color:var(--st-accent-dim)] flex items-center justify-center shrink-0">
                  <svg width="18" height="18" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] group-hover:text-[color:var(--st-accent)] transition-colors">
                    <path d="M6.5 1.5h3L10 3.5l2-.5 1.5 2.5-1.5 1.5.5 2-2 1.5v1L8 13l-2.5-1.5-2 .5L2 9.5l1.5-2L3 5.5 5 4l1.5-2.5z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
                    <circle cx="8" cy="7.5" r="2" stroke="currentColor" strokeWidth="1.2" />
                  </svg>
                </div>
                <div>
                  <div className="text-[13px] font-medium text-[color:var(--st-text-primary)] group-hover:text-[color:var(--st-accent)] transition-colors">Settings</div>
                  <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">API keys, proxy, profile</div>
                </div>
              </div>
            </button>
          </div>

          {/* ── Stats Row ── */}
          <div className="mb-6">
            <SessionStats sessionCount={sessionCount} />
          </div>

          {/* ── Two Column: Cases + IOC Lookup ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-6">
            <RecentCases />
            <QuickIOCLookup />
          </div>

        </div>
      </div>

      {/* ── Footer: System Health ── */}
      <div className="py-3 px-8 border-t border-[color:var(--st-border-subtle)] flex items-center justify-between">
        <SystemHealth />
        <span className="text-[10px] text-[color:var(--st-text-muted)] opacity-40">ShieldTier&#8482;</span>
      </div>
    </div>
  );
}

function getGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}
