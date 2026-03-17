import React, { useState } from 'react';
import type { ProxyConfig } from '../types';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { cn } from '../lib/utils';

interface ProxyModalProps {
  currentConfig: ProxyConfig | null;
  onSave: (config: ProxyConfig) => void;
  onClose: () => void;
}

export function ProxyModal({ currentConfig, onSave, onClose }: ProxyModalProps) {
  const [host, setHost] = useState(currentConfig?.host || '');
  const [port, setPort] = useState(currentConfig?.port?.toString() || '1080');
  const [type, setType] = useState<'socks5' | 'http' | 'direct'>(currentConfig?.type || 'socks5');
  const [username, setUsername] = useState(currentConfig?.username || '');
  const [password, setPassword] = useState(currentConfig?.password || '');
  const [region, setRegion] = useState(currentConfig?.region || '');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const isDirect = type === 'direct';

  const handleTest = async () => {
    if (!host || !port) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await window.shieldtier.proxy.test({ host, port: parseInt(port), type });
      setTestResult(result.success ? 'Connection successful' : `Failed: ${result.error}`);
    } catch (err: any) {
      setTestResult(`Error: ${err.message}`);
    }
    setTesting(false);
  };

  const handleSave = () => {
    if (!isDirect && (!host || !port)) return;
    onSave({
      host: isDirect ? 'localhost' : host,
      port: isDirect ? 0 : parseInt(port),
      type,
      username: username || undefined,
      password: password || undefined,
      region: isDirect ? 'Direct' : (region || undefined),
    });
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in" onClick={onClose}>
      <div
        className="glass rounded-xl border w-[480px] dialog-enter"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-[color:var(--st-border-subtle)]">
          <div>
            <h2 className="text-sm font-semibold text-[color:var(--st-text-primary)]">Configure Proxy (BYOP)</h2>
            <p className="text-[10px] text-[color:var(--st-text-muted)] mt-0.5">Bring Your Own Proxy — connect to any SOCKS5 or HTTP proxy</p>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M4 4L12 12M12 4L4 12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </Button>
        </div>

        {/* Form */}
        <div className="p-4 space-y-4">
          {/* Type selector */}
          <div>
            <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Connection Type</label>
            <div className="flex gap-2">
              {(['socks5', 'http', 'direct'] as const).map(t => (
                <Button
                  key={t}
                  variant={type === t ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setType(t)}
                  className={cn(
                    'flex-1 font-mono',
                    type === t && 'bg-[color:var(--st-accent)]/20 border-[color:var(--st-accent)]/50 text-[color:var(--st-accent)]'
                  )}
                >
                  {t === 'direct' ? 'DIRECT' : t.toUpperCase()}
                </Button>
              ))}
            </div>
            {isDirect && (
              <p className="text-[10px] text-[color:var(--st-warning)] opacity-80 mt-1.5">Direct connection — no proxy, uses your network. For testing only.</p>
            )}
          </div>

          {/* Host + Port (hidden for direct) */}
          {!isDirect && (
            <>
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Host</label>
                  <Input
                    type="text"
                    value={host}
                    onChange={e => setHost(e.target.value)}
                    placeholder="proxy.example.com or 1.2.3.4"
                    className="font-mono"
                  />
                </div>
                <div className="w-24">
                  <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Port</label>
                  <Input
                    type="number"
                    value={port}
                    onChange={e => setPort(e.target.value)}
                    placeholder="1080"
                    className="font-mono"
                  />
                </div>
              </div>

              {/* Auth (optional) */}
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Username (optional)</label>
                  <Input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="proxy username"
                  />
                </div>
                <div className="flex-1">
                  <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Password (optional)</label>
                  <Input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="proxy password"
                  />
                </div>
              </div>

              {/* Region label */}
              <div>
                <label className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Region Label (for fingerprint matching)</label>
                <Input
                  type="text"
                  value={region}
                  onChange={e => setRegion(e.target.value)}
                  placeholder="e.g., US-East, EU-Frankfurt, JP-Tokyo"
                />
              </div>
            </>
          )}

          {/* Test result */}
          {testResult && (
            <div className={cn(
              'text-xs p-2 rounded font-mono',
              testResult.startsWith('Connection') ? 'bg-[color:var(--st-success-dim)] text-[color:var(--st-success)]' : 'bg-[color:var(--st-danger-dim)] text-[color:var(--st-danger)]'
            )}>
              {testResult}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-4 border-t border-[color:var(--st-border-subtle)]">
          {!isDirect ? (
            <Button
              variant="outline"
              size="sm"
              onClick={handleTest}
              disabled={!host || !port || testing}
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </Button>
          ) : <div />}
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={!isDirect && (!host || !port)}
            >
              {isDirect ? 'Use Direct Connection' : 'Save & Connect'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
