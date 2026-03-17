import React, { useState, useEffect } from 'react';
import type { DomainWhitelist } from '../../types';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { SettingsCard } from './SettingsCard';
import { SettingsRow } from './SettingsRow';
import { cn } from '../../lib/utils';

// ═══════════════════════════════════════════════════════
// IntegrationsSection
// ═══════════════════════════════════════════════════════

export function IntegrationsSection() {
  // ── API Keys ──
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [vtKey, setVtKey] = useState('');
  const [abuseKey, setAbuseKey] = useState('');
  const [otxKey, setOtxKey] = useState('');
  const [urlhausKey, setUrlhausKey] = useState('');
  const [mispUrl, setMispUrl] = useState('');
  const [mispKey, setMispKey] = useState('');
  const [apiKeysSaving, setApiKeysSaving] = useState(false);
  const [apiKeysMsg, setApiKeysMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // ── Domain Whitelist ──
  const [whitelistUseBuiltIn, setWhitelistUseBuiltIn] = useState(true);
  const [whitelistDomains, setWhitelistDomains] = useState('');
  const [whitelistPatterns, setWhitelistPatterns] = useState('');
  const [whitelistSaving, setWhitelistSaving] = useState(false);
  const [whitelistMsg, setWhitelistMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // ── Load masked enrichment API keys on mount ──
  useEffect(() => {
    window.shieldtier.enrichment.getAPIKeys().then((masked) => {
      setApiKeys(masked);
    }).catch(() => {});
  }, []);

  // ── Load whitelist on mount ──
  useEffect(() => {
    window.shieldtier.config.getWhitelist().then((wl: DomainWhitelist) => {
      setWhitelistUseBuiltIn(wl.useBuiltIn);
      setWhitelistDomains(wl.domains.join('\n'));
      setWhitelistPatterns(wl.patterns.join('\n'));
    }).catch(() => {});
  }, []);

  const handleSaveAPIKeys = async () => {
    setApiKeysSaving(true);
    setApiKeysMsg(null);
    try {
      const keysToSave: Record<string, string> = {};
      if (vtKey.trim()) keysToSave.virustotal = vtKey.trim();
      if (abuseKey.trim()) keysToSave.abuseipdb = abuseKey.trim();
      if (otxKey.trim()) keysToSave.otx = otxKey.trim();
      if (urlhausKey.trim()) keysToSave.urlhaus = urlhausKey.trim();
      if (mispUrl.trim()) keysToSave.misp_url = mispUrl.trim();
      if (mispKey.trim()) keysToSave.misp = mispKey.trim();
      await window.shieldtier.enrichment.setAPIKeys(keysToSave);
      const fresh = await window.shieldtier.enrichment.getAPIKeys();
      setApiKeys(fresh);
      setApiKeysMsg({ type: 'success', text: 'API keys saved.' });
    } catch (err: any) {
      setApiKeysMsg({ type: 'error', text: err.message || 'Failed to save API keys.' });
    }
    setApiKeysSaving(false);
  };

  const handleSaveWhitelist = async () => {
    setWhitelistSaving(true);
    setWhitelistMsg(null);
    try {
      const wl: DomainWhitelist = {
        useBuiltIn: whitelistUseBuiltIn,
        domains: whitelistDomains.split('\n').map(d => d.trim()).filter(Boolean),
        patterns: whitelistPatterns.split('\n').map(p => p.trim()).filter(Boolean),
      };
      await window.shieldtier.config.setWhitelist(wl);
      setWhitelistMsg({ type: 'success', text: 'Whitelist saved.' });
    } catch (err: any) {
      setWhitelistMsg({ type: 'error', text: err.message || 'Failed to save whitelist.' });
    }
    setWhitelistSaving(false);
  };

  const API_KEY_FIELDS = [
    { id: 'api-virustotal', label: 'VirusTotal', key: 'virustotal', value: vtKey, setter: setVtKey, type: 'password' as const },
    { id: 'api-abuseipdb', label: 'AbuseIPDB', key: 'abuseipdb', value: abuseKey, setter: setAbuseKey, type: 'password' as const },
    { id: 'api-otx', label: 'AlienVault OTX', key: 'otx', value: otxKey, setter: setOtxKey, type: 'password' as const },
    { id: 'api-urlhaus', label: 'URLhaus', key: 'urlhaus', value: urlhausKey, setter: setUrlhausKey, type: 'password' as const },
    { id: 'api-misp-url', label: 'MISP Instance URL', key: 'misp_url', value: mispUrl, setter: setMispUrl, type: 'text' as const },
    { id: 'api-misp-key', label: 'MISP API Key', key: 'misp', value: mispKey, setter: setMispKey, type: 'password' as const },
  ];

  return (
    <div className="space-y-4">
      <div className="mb-2">
        <h2 className="text-base font-semibold text-[color:var(--st-text-primary)]">Integrations</h2>
        <p className="text-xs text-[color:var(--st-text-muted)] mt-1">API keys, enrichment providers, and domain whitelist.</p>
      </div>

      {/* ── Card 1: Threat Intelligence API Keys ── */}
      <SettingsCard
        title="Threat Intelligence API Keys"
        description="Keys are encrypted at rest with your golden key."
        footer={
          <div className="flex items-center gap-3">
            <Button
              size="sm"
              onClick={handleSaveAPIKeys}
              disabled={apiKeysSaving}
            >
              {apiKeysSaving ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-3 w-3" viewBox="0 0 12 12" fill="none">
                    <circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.5" opacity="0.25" />
                    <path d="M11 6a5 5 0 00-5-5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  Saving
                </span>
              ) : 'Save API Keys'}
            </Button>
            {apiKeysMsg && (
              <span
                role={apiKeysMsg.type === 'success' ? 'status' : 'alert'}
                aria-live={apiKeysMsg.type === 'success' ? 'polite' : undefined}
                className={`text-xs ${apiKeysMsg.type === 'success' ? 'text-green-400' : 'text-red-400'}`}
              >
                {apiKeysMsg.text}
              </span>
            )}
          </div>
        }
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {API_KEY_FIELDS.map((field) => (
            <div key={field.id}>
              <label htmlFor={field.id} className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">{field.label}</label>
              <Input
                id={field.id}
                type={field.type}
                value={field.value}
                onChange={(e) => field.setter(e.target.value)}
                className="font-mono"
                placeholder={apiKeys[field.key] ? `Current: ${apiKeys[field.key]}` : field.type === 'text' ? 'e.g. https://misp.yourorg.com' : 'Enter API key'}
              />
            </div>
          ))}
        </div>
      </SettingsCard>

      {/* ── Card 2: Domain Whitelist ── */}
      <SettingsCard
        title="Domain Whitelist"
        description="Whitelisted domains are excluded from IOC enrichment to reduce noise from known-good infrastructure."
        footer={
          <div className="flex items-center gap-3">
            <Button
              size="sm"
              onClick={handleSaveWhitelist}
              disabled={whitelistSaving}
            >
              {whitelistSaving ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-3 w-3" viewBox="0 0 12 12" fill="none">
                    <circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.5" opacity="0.25" />
                    <path d="M11 6a5 5 0 00-5-5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  Saving
                </span>
              ) : 'Save Whitelist'}
            </Button>
            {whitelistMsg && (
              <span
                role={whitelistMsg.type === 'success' ? 'status' : 'alert'}
                aria-live={whitelistMsg.type === 'success' ? 'polite' : undefined}
                className={`text-xs ${whitelistMsg.type === 'success' ? 'text-green-400' : 'text-red-400'}`}
              >
                {whitelistMsg.text}
              </span>
            )}
          </div>
        }
      >
        {/* Built-in CDN Whitelist Toggle */}
        <SettingsRow label="Built-in CDN Whitelist" description="Google, Cloudflare, AWS, Microsoft, etc.">
          <button
            type="button"
            role="checkbox"
            aria-checked={whitelistUseBuiltIn}
            onClick={() => setWhitelistUseBuiltIn(!whitelistUseBuiltIn)}
            className={cn(
              'w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--st-accent)]/50',
              whitelistUseBuiltIn
                ? 'bg-[color:var(--st-accent)] border-[color:var(--st-accent)]'
                : 'border-[color:var(--st-border)] bg-transparent hover:border-[color:var(--st-text-muted)]'
            )}
          >
            {whitelistUseBuiltIn && (
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                <path d="M2 5.5L4 7.5L8 3" stroke="white" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </button>
        </SettingsRow>

        {/* Custom Domains */}
        <div>
          <label htmlFor="whitelist-domains" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Custom Domains (one per line)</label>
          <textarea
            id="whitelist-domains"
            value={whitelistDomains}
            onChange={(e) => setWhitelistDomains(e.target.value)}
            rows={4}
            className="w-full glass-input border rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-blue-500 font-mono resize-y"
            placeholder={"example.com\ncdn.mycompany.com\ninternal.corp.net"}
          />
        </div>

        {/* Wildcard Patterns */}
        <div>
          <label htmlFor="whitelist-patterns" className="text-xs text-[color:var(--st-text-secondary)] block mb-1.5">Wildcard Patterns (one per line)</label>
          <textarea
            id="whitelist-patterns"
            value={whitelistPatterns}
            onChange={(e) => setWhitelistPatterns(e.target.value)}
            rows={4}
            className="w-full glass-input border rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-blue-500 font-mono resize-y"
            placeholder={"*.googleapis.com\n*.cloudfront.net\n*.azureedge.net"}
          />
        </div>
      </SettingsCard>
    </div>
  );
}
