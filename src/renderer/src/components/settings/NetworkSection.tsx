import React, { useState } from 'react';
import type { ProxyConfig } from '../../types';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { SettingsCard } from './SettingsCard';
import { cn } from '../../lib/utils';

// ═══════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════

export interface NetworkSectionProps {
  proxyConfig: ProxyConfig | null;
  onProxyConfigured: (config: ProxyConfig) => void;
}

// ═══════════════════════════════════════════════════════
// NetworkSection
// ═══════════════════════════════════════════════════════

export function NetworkSection({ proxyConfig, onProxyConfigured }: NetworkSectionProps) {
  const [proxyType, setProxyType] = useState<'socks5' | 'http' | 'direct'>(proxyConfig?.type || 'socks5');
  const [proxyHost, setProxyHost] = useState(proxyConfig?.host || '');
  const [proxyPort, setProxyPort] = useState(proxyConfig?.port?.toString() || '1080');
  const [proxyUsername, setProxyUsername] = useState(proxyConfig?.username || '');
  const [proxyPassword, setProxyPassword] = useState(proxyConfig?.password || '');
  const [proxyRegion, setProxyRegion] = useState(proxyConfig?.region || '');
  const [proxyTesting, setProxyTesting] = useState(false);
  const [proxyTestResult, setProxyTestResult] = useState<string | null>(null);

  const handleTestProxy = async () => {
    if (proxyType !== 'direct' && (!proxyHost || !proxyPort)) return;
    setProxyTesting(true);
    setProxyTestResult(null);
    try {
      const config: ProxyConfig = {
        host: proxyHost,
        port: parseInt(proxyPort),
        type: proxyType,
      };
      const result = await window.shieldtier.proxy.test(config);
      setProxyTestResult(result.success ? `Connection successful${result.ip ? ` — IP: ${result.ip}` : ''}` : `Failed: ${result.error}`);
    } catch (err: any) {
      setProxyTestResult(`Error: ${err.message}`);
    }
    setProxyTesting(false);
  };

  const handleSaveProxy = () => {
    const isDirect = proxyType === 'direct';
    if (!isDirect && (!proxyHost || !proxyPort)) return;
    onProxyConfigured({
      host: isDirect ? 'localhost' : proxyHost,
      port: isDirect ? 0 : parseInt(proxyPort),
      type: proxyType,
      username: proxyUsername || undefined,
      password: proxyPassword || undefined,
      region: isDirect ? 'Direct' : (proxyRegion || undefined),
    });
  };

  const isDirect = proxyType === 'direct';

  return (
    <div className="space-y-4">
      <div className="mb-2">
        <h2 className="text-base font-semibold text-[color:var(--st-text-primary)]">Network</h2>
        <p className="text-xs text-[color:var(--st-text-muted)] mt-1">Configure proxy connections for investigation isolation.</p>
      </div>

      <SettingsCard
        title="Proxy Configuration"
        footer={
          <div className="space-y-3">
            {/* Test Result */}
            {proxyTestResult && (
              <div
                role="status"
                aria-live="polite"
                className={cn(
                  'text-xs p-3 rounded-lg',
                  proxyTestResult.startsWith('Connection')
                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                    : 'bg-red-500/10 text-red-400 border border-red-500/20'
                )}
              >
                {proxyTestResult}
              </div>
            )}
            <div className="flex items-center gap-3">
              {!isDirect && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleTestProxy}
                  disabled={!proxyHost || !proxyPort || proxyTesting}
                >
                  {proxyTesting ? 'Testing...' : 'Test Connection'}
                </Button>
              )}
              <Button
                size="sm"
                onClick={handleSaveProxy}
                disabled={!isDirect && (!proxyHost || !proxyPort)}
              >
                {isDirect ? 'Use Direct Connection' : 'Save & Connect'}
              </Button>
            </div>
          </div>
        }
      >
        {/* Connection Type */}
        <div>
          <label id="conn-type-label" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Connection Type</label>
          <div className="flex gap-2" role="radiogroup" aria-labelledby="conn-type-label">
            {(['socks5', 'http', 'direct'] as const).map((t) => (
              <Button
                key={t}
                variant="outline"
                size="sm"
                role="radio"
                aria-checked={proxyType === t}
                onClick={() => setProxyType(t)}
                className={cn(
                  'flex-1',
                  proxyType === t && 'bg-[color:var(--st-accent-dim)] border-[color:var(--st-accent)]/50 text-[color:var(--st-accent)]'
                )}
              >
                {t === 'direct' ? 'DIRECT' : t.toUpperCase()}
              </Button>
            ))}
          </div>
          {isDirect && (
            <p className="text-[10px] text-yellow-500/80 mt-1.5">Direct connection — no proxy, uses your network. For testing only.</p>
          )}
        </div>

        {/* Host + Port */}
        {!isDirect && (
          <>
            <div className="flex gap-3">
              <div className="flex-1">
                <label htmlFor="proxy-host" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Host</label>
                <Input
                  id="proxy-host"
                  type="text"
                  value={proxyHost}
                  onChange={(e) => setProxyHost(e.target.value)}
                  placeholder="proxy.example.com or 1.2.3.4"
                  className="font-mono"
                />
              </div>
              <div className="w-24">
                <label htmlFor="proxy-port" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Port</label>
                <Input
                  id="proxy-port"
                  type="number"
                  value={proxyPort}
                  onChange={(e) => setProxyPort(e.target.value)}
                  placeholder="1080"
                  className="font-mono"
                />
              </div>
            </div>

            {/* Auth (optional) */}
            <div className="flex gap-3">
              <div className="flex-1">
                <label htmlFor="proxy-username" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Username (optional)</label>
                <Input
                  id="proxy-username"
                  type="text"
                  value={proxyUsername}
                  onChange={(e) => setProxyUsername(e.target.value)}
                  placeholder="proxy username"
                />
              </div>
              <div className="flex-1">
                <label htmlFor="proxy-password" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Password (optional)</label>
                <Input
                  id="proxy-password"
                  type="password"
                  value={proxyPassword}
                  onChange={(e) => setProxyPassword(e.target.value)}
                  placeholder="proxy password"
                />
              </div>
            </div>

            {/* Region */}
            <div>
              <label htmlFor="proxy-region" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Region Label</label>
              <Input
                id="proxy-region"
                type="text"
                value={proxyRegion}
                onChange={(e) => setProxyRegion(e.target.value)}
                placeholder="e.g., US-East, EU-Frankfurt, JP-Tokyo"
              />
            </div>
          </>
        )}
      </SettingsCard>
    </div>
  );
}
