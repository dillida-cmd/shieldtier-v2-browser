import React, { useState, useEffect, useCallback } from 'react';
import type {
  InvestigationSession,
  ThreatFeedConfig,
  ThreatFeedMatch,
  TAXIIServerInfo,
  TAXIICollection,
  ThreatFeedAuthType,
  ThreatSeverity,
  FeedMatcherStats,
} from '../types';

interface ThreatFeedPanelProps {
  session: InvestigationSession;
}

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const SEVERITY_BG: Record<ThreatSeverity, string> = {
  critical: 'rgba(239,68,68,0.15)',
  high: 'rgba(249,115,22,0.15)',
  medium: 'rgba(234,179,8,0.15)',
  low: 'rgba(59,130,246,0.15)',
  info: 'rgba(107,114,128,0.15)',
};

function timeAgo(ts: number): string {
  if (!ts) return 'never';
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function formatPollInterval(ms: number): string {
  if (!ms) return 'Manual';
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m`;
  return `${Math.floor(ms / 3_600_000)}h`;
}

export default function ThreatFeedPanel({ session }: ThreatFeedPanelProps) {
  const [feeds, setFeeds] = useState<ThreatFeedConfig[]>([]);
  const [matches, setMatches] = useState<ThreatFeedMatch[]>([]);
  const [stats, setStats] = useState<FeedMatcherStats>({ totalIOCs: 0, feedBreakdown: {} });
  const [selectedFeedId, setSelectedFeedId] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showImport, setShowImport] = useState<'csv' | 'stix' | null>(null);

  // Load feeds, matches, stats on mount
  const refresh = useCallback(async () => {
    const [feedList, matchList, feedStats] = await Promise.all([
      window.shieldtier.threatfeed.listFeeds(),
      window.shieldtier.threatfeed.getMatches(session.id),
      window.shieldtier.threatfeed.getStats(),
    ]);
    setFeeds(feedList);
    setMatches(matchList);
    setStats(feedStats);
  }, [session.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Listen for live matches and sync status
  useEffect(() => {
    const unsubMatch = window.shieldtier.threatfeed.onMatch((match) => {
      if (match.sessionId === session.id) {
        setMatches(prev => [...prev, match]);
      }
    });
    const unsubSync = window.shieldtier.threatfeed.onSyncStatus(() => {
      refresh();
    });
    return () => { unsubMatch(); unsubSync(); };
  }, [session.id, refresh]);

  const selectedFeed = feeds.find(f => f.id === selectedFeedId) || null;

  return (
    <div className="flex flex-col h-full text-[color:var(--st-text-primary)]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[color:var(--st-border)]">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-[color:var(--st-text-primary)]">Threat Intelligence Feeds</h2>
          <span className="text-xs text-[color:var(--st-text-muted)]">
            {feeds.length} feed{feeds.length !== 1 ? 's' : ''} · {stats.totalIOCs.toLocaleString()} indicators · {matches.length} match{matches.length !== 1 ? 'es' : ''}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            aria-label="Add Feed"
            className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors focus-visible:ring-2 focus-visible:ring-blue-400/60 focus-visible:outline-none"
          >
            + Add Feed
          </button>
        </div>
      </div>

      {/* Main content area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel: Feed list */}
        <div className="w-64 shrink-0 min-w-0 border-r border-[color:var(--st-border)] flex flex-col overflow-y-auto">
          {feeds.length === 0 && !showAddForm && (
            <div className="p-4 text-xs text-[color:var(--st-text-muted)] text-center">
              No feeds configured.<br />Add a TAXII feed or import IOCs.
            </div>
          )}
          {feeds.map(feed => (
            <button
              key={feed.id}
              onClick={() => setSelectedFeedId(feed.id)}
              title={feed.serverUrl || feed.name}
              className={`w-full text-left px-3 py-2.5 border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-bg-elevated)] transition-colors focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-400/60 focus-visible:outline-none ${
                selectedFeedId === feed.id ? 'bg-[color:var(--st-bg-elevated)] border-l-2 border-l-blue-500' : ''
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${feed.enabled ? 'bg-green-500' : 'bg-gray-500'}`} />
                <span className="text-xs font-medium text-[color:var(--st-text-primary)] truncate">{feed.name}</span>
              </div>
              <div className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5 pl-4 truncate" title={`${feed.indicatorCount.toLocaleString()} IOCs · ${timeAgo(feed.lastSyncTimestamp)}`}>
                {feed.indicatorCount.toLocaleString()} IOCs · {timeAgo(feed.lastSyncTimestamp)}
              </div>
            </button>
          ))}

          {/* Import buttons */}
          <div className="p-3 mt-auto border-t border-[color:var(--st-border)] space-y-2">
            <button
              onClick={() => setShowImport('csv')}
              className="w-full px-3 py-1.5 text-xs bg-[color:var(--st-bg-elevated)] hover:bg-[color:var(--st-accent-dim)] rounded transition-colors"
            >
              Import CSV
            </button>
            <button
              onClick={() => setShowImport('stix')}
              className="w-full px-3 py-1.5 text-xs bg-[color:var(--st-bg-elevated)] hover:bg-[color:var(--st-accent-dim)] rounded transition-colors"
            >
              Import STIX JSON
            </button>
          </div>
        </div>

        {/* Right panel: Detail / Matches / Add form */}
        <div className="flex-1 overflow-y-auto">
          {showAddForm && (
            <AddFeedForm
              onAdded={() => { setShowAddForm(false); refresh(); }}
              onCancel={() => setShowAddForm(false)}
            />
          )}

          {showImport && (
            <ImportForm
              type={showImport}
              onDone={() => { setShowImport(null); refresh(); }}
              onCancel={() => setShowImport(null)}
            />
          )}

          {!showAddForm && !showImport && selectedFeed && (
            <FeedDetail
              feed={selectedFeed}
              matches={matches.filter(m => m.ioc.feedId === selectedFeed.id)}
              onRefresh={refresh}
            />
          )}

          {!showAddForm && !showImport && !selectedFeed && (
            <div className="flex-1 p-4">
              {/* Show all matches */}
              <h3 className="text-xs font-semibold text-[color:var(--st-text-primary)] mb-3">Session Matches</h3>
              {matches.length === 0 ? (
                <div className="text-xs text-[color:var(--st-text-muted)]">No matches yet. Browse to a URL to check against loaded indicators.</div>
              ) : (
                <div className="space-y-2">
                  {matches.map((match, i) => (
                    <MatchCard key={i} match={match} />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Feed Detail
// ═══════════════════════════════════════════════════════

function FeedDetail({ feed, matches, onRefresh }: { feed: ThreatFeedConfig; matches: ThreatFeedMatch[]; onRefresh: () => void }) {
  const [syncing, setSyncing] = useState(false);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await window.shieldtier.threatfeed.syncFeed(feed.id);
    } catch {}
    setSyncing(false);
    onRefresh();
  };

  const handleToggle = async () => {
    await window.shieldtier.threatfeed.toggleFeed(feed.id, !feed.enabled);
    onRefresh();
  };

  const handleDelete = async () => {
    await window.shieldtier.threatfeed.deleteFeed(feed.id);
    onRefresh();
  };

  const statusColor = feed.lastSyncStatus === 'synced' ? '#22c55e' : feed.lastSyncStatus === 'error' ? '#ef4444' : feed.lastSyncStatus === 'syncing' ? '#eab308' : '#6b7280';

  return (
    <div className="p-4 space-y-4">
      {/* Feed info */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-[color:var(--st-text-primary)]">{feed.name}</h3>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {feed.serverUrl && (
            <><span className="text-[color:var(--st-text-muted)]">Server:</span><span className="truncate" title={feed.serverUrl}>{feed.serverUrl}</span></>
          )}
          {feed.collectionId && (
            <><span className="text-[color:var(--st-text-muted)]">Collection:</span><span className="truncate" title={feed.collectionId}>{feed.collectionId}</span></>
          )}
          <span className="text-[color:var(--st-text-muted)]">Status:</span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
            {feed.lastSyncStatus === 'synced' ? `Synced (${timeAgo(feed.lastSyncTimestamp)})` : feed.lastSyncStatus}
          </span>
          <span className="text-[color:var(--st-text-muted)]">Indicators:</span>
          <span>{feed.indicatorCount.toLocaleString()}</span>
          <span className="text-[color:var(--st-text-muted)]">Poll Interval:</span>
          <span>{formatPollInterval(feed.pollIntervalMs)}</span>
          <span className="text-[color:var(--st-text-muted)]">Auth:</span>
          <span>{feed.authType === 'none' ? 'None' : feed.authType === 'basic' ? 'Basic Auth' : 'API Key'}</span>
        </div>
        {feed.lastError && (
          <div className="text-xs text-red-400 bg-red-900/20 px-2 py-1 rounded">{feed.lastError}</div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={handleSync}
          disabled={syncing}
          className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded transition-colors"
        >
          {syncing ? 'Syncing...' : 'Sync Now'}
        </button>
        <button
          onClick={handleToggle}
          className={`px-3 py-1.5 text-xs rounded transition-colors ${
            feed.enabled ? 'bg-yellow-600/20 text-yellow-400 hover:bg-yellow-600/30' : 'bg-green-600/20 text-green-400 hover:bg-green-600/30'
          }`}
        >
          {feed.enabled ? 'Disable' : 'Enable'}
        </button>
        <button
          onClick={handleDelete}
          className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 hover:bg-red-600/30 rounded transition-colors"
        >
          Delete
        </button>
      </div>

      {/* Matches for this feed */}
      <div>
        <h4 className="text-xs font-semibold text-[color:var(--st-text-primary)] mb-2">Session Matches ({matches.length})</h4>
        {matches.length === 0 ? (
          <div className="text-xs text-[color:var(--st-text-muted)]">No matches from this feed yet.</div>
        ) : (
          <div className="space-y-2">
            {matches.map((match, i) => (
              <MatchCard key={i} match={match} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Match Card
// ═══════════════════════════════════════════════════════

function MatchCard({ match }: { match: ThreatFeedMatch }) {
  const sev = match.ioc.severity;
  return (
    <div
      className="px-3 py-2 rounded border text-xs"
      style={{ borderColor: SEVERITY_COLORS[sev], backgroundColor: SEVERITY_BG[sev] }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono font-bold" style={{ color: SEVERITY_COLORS[sev] }}>{match.matchedValue}</span>
          <span className="text-[color:var(--st-text-muted)]">{match.ioc.feedName}</span>
          <span className="uppercase font-bold text-[10px] px-1.5 py-0.5 rounded" style={{ color: SEVERITY_COLORS[sev], backgroundColor: SEVERITY_BG[sev] }}>
            {sev}
          </span>
        </div>
        <span className="text-[color:var(--st-text-muted)] text-[10px]">{match.matchSource}</span>
      </div>
      <div className="mt-1 text-[color:var(--st-text-muted)] truncate">{match.harEntryUrl}</div>
      {match.ioc.mitre && (
        <span className="inline-block mt-1 text-[10px] text-purple-400 bg-purple-900/20 px-1.5 py-0.5 rounded">{match.ioc.mitre}</span>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Add Feed Form
// ═══════════════════════════════════════════════════════

function AddFeedForm({ onAdded, onCancel }: { onAdded: () => void; onCancel: () => void }) {
  const [name, setName] = useState('');
  const [serverUrl, setServerUrl] = useState('');
  const [authType, setAuthType] = useState<ThreatFeedAuthType>('none');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [pollInterval, setPollInterval] = useState('3600000');
  const [discovering, setDiscovering] = useState(false);
  const [serverInfo, setServerInfo] = useState<TAXIIServerInfo | null>(null);
  const [apiRoots, setApiRoots] = useState<string[]>([]);
  const [selectedApiRoot, setSelectedApiRoot] = useState('');
  const [collections, setCollections] = useState<TAXIICollection[]>([]);
  const [selectedCollection, setSelectedCollection] = useState('');
  const [loadingCollections, setLoadingCollections] = useState(false);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const buildAuth = () => ({ type: authType, username, password, apiKey });

  const handleDiscover = async () => {
    if (!serverUrl.trim()) return;
    setDiscovering(true);
    setError('');
    setServerInfo(null);
    setCollections([]);
    try {
      const info = await window.shieldtier.threatfeed.discover(serverUrl.trim(), buildAuth());
      setServerInfo(info);
      setApiRoots(info.apiRoots);
      if (info.apiRoots.length > 0) {
        setSelectedApiRoot(info.apiRoots[0]);
      }
    } catch (err: any) {
      setError(err.message || 'Discovery failed');
    }
    setDiscovering(false);
  };

  const handleLoadCollections = async () => {
    if (!selectedApiRoot) return;
    setLoadingCollections(true);
    setError('');
    try {
      // Create a temporary feed to load collections
      const tempFeed = await window.shieldtier.threatfeed.addFeed({
        name: name || 'Temp',
        serverUrl: serverUrl.trim(),
        apiRootPath: selectedApiRoot,
        collectionId: '',
        authType,
        username,
        password,
        apiKey,
        enabled: false,
      });
      const cols = await window.shieldtier.threatfeed.getCollections(tempFeed.id);
      setCollections(cols.filter(c => c.canRead));
      if (cols.length > 0) setSelectedCollection(cols[0].id);
      // Delete temp feed
      await window.shieldtier.threatfeed.deleteFeed(tempFeed.id);
    } catch (err: any) {
      setError(err.message || 'Failed to load collections');
    }
    setLoadingCollections(false);
  };

  // Auto-load collections when apiRoot is selected
  useEffect(() => {
    if (selectedApiRoot && serverInfo) {
      handleLoadCollections();
    }
  }, [selectedApiRoot]);

  const handleSave = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    setSaving(true);
    setError('');
    try {
      await window.shieldtier.threatfeed.addFeed({
        name: name.trim(),
        serverUrl: serverUrl.trim(),
        apiRootPath: selectedApiRoot,
        collectionId: selectedCollection,
        authType,
        username,
        password,
        apiKey,
        enabled: true,
        pollIntervalMs: parseInt(pollInterval) || 3_600_000,
      });
      onAdded();
    } catch (err: any) {
      setError(err.message || 'Failed to add feed');
    }
    setSaving(false);
  };

  return (
    <div className="p-4 border-b border-[color:var(--st-border)]">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-[color:var(--st-text-primary)]">Add TAXII Feed</h3>
        <button onClick={onCancel} className="text-xs text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]">Cancel</button>
      </div>

      <div className="space-y-3 max-w-lg">
        {/* Name */}
        <div>
          <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Feed Name</label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g., AlienVault OTX"
            className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] focus:border-blue-500 outline-none"
          />
        </div>

        {/* Server URL */}
        <div>
          <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">TAXII Server URL</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={serverUrl}
              onChange={e => setServerUrl(e.target.value)}
              placeholder="https://taxii.example.com"
              className="flex-1 px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] focus:border-blue-500 outline-none"
            />
            <button
              onClick={handleDiscover}
              disabled={discovering || !serverUrl.trim()}
              className="px-3 py-1.5 text-xs bg-[color:var(--st-bg-elevated)] hover:bg-[color:var(--st-accent-dim)] disabled:opacity-50 rounded transition-colors"
            >
              {discovering ? 'Discovering...' : 'Discover'}
            </button>
          </div>
        </div>

        {/* Auth */}
        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Auth</label>
            <select
              value={authType}
              onChange={e => setAuthType(e.target.value as ThreatFeedAuthType)}
              className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none"
            >
              <option value="none">None</option>
              <option value="basic">Basic</option>
              <option value="apikey">API Key</option>
            </select>
          </div>
          {authType === 'basic' && (
            <>
              <div>
                <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Username</label>
                <input type="text" value={username} onChange={e => setUsername(e.target.value)}
                  className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none" />
              </div>
              <div>
                <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none" />
              </div>
            </>
          )}
          {authType === 'apikey' && (
            <div className="col-span-2">
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">API Key</label>
              <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none" />
            </div>
          )}
        </div>

        {/* Server info / API roots */}
        {serverInfo && (
          <div className="text-xs text-green-400 bg-green-900/20 px-2 py-1.5 rounded">
            Connected: {serverInfo.title} ({apiRoots.length} API root{apiRoots.length !== 1 ? 's' : ''})
          </div>
        )}

        {apiRoots.length > 1 && (
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">API Root</label>
            <select
              value={selectedApiRoot}
              onChange={e => setSelectedApiRoot(e.target.value)}
              className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none"
            >
              {apiRoots.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
        )}

        {/* Collections */}
        {collections.length > 0 && (
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Collection</label>
            <select
              value={selectedCollection}
              onChange={e => setSelectedCollection(e.target.value)}
              className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none"
            >
              {collections.map(c => (
                <option key={c.id} value={c.id}>{c.title} ({c.id})</option>
              ))}
            </select>
          </div>
        )}
        {loadingCollections && <div className="text-xs text-[color:var(--st-text-muted)]">Loading collections...</div>}

        {/* Poll interval */}
        <div>
          <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Poll Interval</label>
          <select
            value={pollInterval}
            onChange={e => setPollInterval(e.target.value)}
            className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none"
          >
            <option value="0">Manual only</option>
            <option value="900000">15 minutes</option>
            <option value="1800000">30 minutes</option>
            <option value="3600000">1 hour</option>
            <option value="14400000">4 hours</option>
            <option value="86400000">24 hours</option>
          </select>
        </div>

        {error && <div className="text-xs text-red-400">{error}</div>}

        <button
          onClick={handleSave}
          disabled={saving || !name.trim()}
          className="px-4 py-2 text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded transition-colors"
        >
          {saving ? 'Adding...' : 'Add Feed'}
        </button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Import Form (CSV / STIX)
// ═══════════════════════════════════════════════════════

function ImportForm({ type, onDone, onCancel }: { type: 'csv' | 'stix'; onDone: () => void; onCancel: () => void }) {
  const [name, setName] = useState(type === 'csv' ? 'CSV Import' : 'STIX Import');
  const [content, setContent] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  const handleImport = async () => {
    if (!content.trim()) return;
    setImporting(true);
    try {
      const res = type === 'csv'
        ? await window.shieldtier.threatfeed.importCSV(content, name)
        : await window.shieldtier.threatfeed.importSTIX(content, name);
      setResult(`Imported ${res.imported} indicators (${res.duplicates} duplicates, ${res.errors} errors)`);
      setTimeout(() => onDone(), 1500);
    } catch (err: any) {
      setResult(`Error: ${err.message}`);
    }
    setImporting(false);
  };

  return (
    <div className="p-4 border-b border-[color:var(--st-border)]">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-[color:var(--st-text-primary)]">Import {type === 'csv' ? 'CSV' : 'STIX JSON'}</h3>
        <button onClick={onCancel} className="text-xs text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]">Cancel</button>
      </div>
      <div className="space-y-3 max-w-lg">
        <div>
          <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Feed Name</label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] outline-none"
          />
        </div>
        <div>
          <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">
            {type === 'csv' ? 'CSV Data (columns: value, type, severity, description)' : 'STIX 2.1 Bundle JSON'}
          </label>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            rows={10}
            placeholder={type === 'csv'
              ? 'value,type,severity,description\n1.2.3.4,ip,high,Known C2 server\nevil.com,domain,critical,Phishing domain'
              : '{"type":"bundle","id":"bundle--...","objects":[...]}'
            }
            className="w-full px-2 py-1.5 text-xs bg-[color:var(--st-bg-panel)] border border-[color:var(--st-accent-dim)] rounded text-[color:var(--st-text-primary)] font-mono outline-none resize-y"
          />
        </div>
        {result && (
          <div className={`text-xs px-2 py-1.5 rounded ${result.startsWith('Error') ? 'text-red-400 bg-red-900/20' : 'text-green-400 bg-green-900/20'}`}>
            {result}
          </div>
        )}
        <button
          onClick={handleImport}
          disabled={importing || !content.trim()}
          className="px-4 py-2 text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded transition-colors"
        >
          {importing ? 'Importing...' : 'Import'}
        </button>
      </div>
    </div>
  );
}
