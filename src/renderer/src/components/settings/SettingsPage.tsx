import React, { useState } from 'react';
import type { AuthUser, ProxyConfig } from '../../types';
import { AccountSection } from './AccountSection';
import { AppearanceSection } from './AppearanceSection';
import { PrivacySection } from './PrivacySection';
import { NetworkSection } from './NetworkSection';
import { IntegrationsSection } from './IntegrationsSection';
import { AboutSection } from './AboutSection';
import { cn } from '../../lib/utils';

// ═══════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════

interface SettingsPageProps {
  user: AuthUser;
  avatar: string;
  proxyConfig: ProxyConfig | null;
  onAvatarChange: (avatar: string) => void;
  onUserUpdated: (user: AuthUser) => void;
  onProxyConfigured: (config: ProxyConfig) => void;
  onClose: () => void;
  onLogout: () => void;
}

type SettingsSection = 'account' | 'appearance' | 'privacy' | 'network' | 'integrations' | 'about';

// ═══════════════════════════════════════════════════════
// Nav Items
// ═══════════════════════════════════════════════════════

const NAV_ITEMS: { key: SettingsSection; label: string; icon: JSX.Element }[] = [
  {
    key: 'account',
    label: 'Account',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="5.5" r="2.8" stroke="currentColor" strokeWidth="1.2" />
        <path d="M3 14c0-2.8 2.2-5 5-5s5 2.2 5 5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    key: 'appearance',
    label: 'Appearance',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <path d="M8 1C4.1 1 1 4.1 1 8s3.1 7 7 7c.8 0 1.4-.6 1.4-1.4 0-.4-.1-.7-.3-.9-.2-.2-.3-.5-.3-.9 0-.8.6-1.4 1.4-1.4H11c2.2 0 4-1.8 4-4 0-3.3-3.1-6.4-7-6.4z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
        <circle cx="4.8" cy="7" r="1" fill="currentColor" opacity="0.7" />
        <circle cx="7" cy="4.5" r="1" fill="currentColor" opacity="0.7" />
        <circle cx="10" cy="4.5" r="1" fill="currentColor" opacity="0.7" />
        <circle cx="12" cy="7" r="1" fill="currentColor" opacity="0.7" />
      </svg>
    ),
  },
  {
    key: 'privacy',
    label: 'Privacy & Security',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <path d="M8 1.5L2.5 4v4c0 3.3 2.3 6.2 5.5 7 3.2-.8 5.5-3.7 5.5-7V4L8 1.5z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    key: 'network',
    label: 'Network',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" />
        <ellipse cx="8" cy="8" rx="3" ry="6" stroke="currentColor" strokeWidth="1.2" />
        <line x1="2" y1="8" x2="14" y2="8" stroke="currentColor" strokeWidth="1.2" />
      </svg>
    ),
  },
  {
    key: 'integrations',
    label: 'Integrations',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <rect x="1.5" y="1.5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.2" />
        <rect x="9.5" y="1.5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.2" />
        <rect x="1.5" y="9.5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.2" />
        <rect x="9.5" y="9.5" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.2" />
      </svg>
    ),
  },
  {
    key: 'about',
    label: 'About',
    icon: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2" />
        <path d="M8 7v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="8" cy="4.5" r="0.75" fill="currentColor" />
      </svg>
    ),
  },
];

// ═══════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════

export function SettingsPage({
  user,
  avatar,
  proxyConfig,
  onAvatarChange,
  onUserUpdated,
  onProxyConfigured,
  onClose,
  onLogout,
}: SettingsPageProps) {
  const [activeSection, setActiveSection] = useState<SettingsSection>('account');

  const renderSection = () => {
    switch (activeSection) {
      case 'account':
        return <AccountSection user={user} avatar={avatar} onAvatarChange={onAvatarChange} onUserUpdated={onUserUpdated} onLogout={onLogout} />;
      case 'appearance':
        return <AppearanceSection />;
      case 'privacy':
        return <PrivacySection />;
      case 'network':
        return <NetworkSection proxyConfig={proxyConfig} onProxyConfigured={onProxyConfigured} />;
      case 'integrations':
        return <IntegrationsSection />;
      case 'about':
        return <AboutSection />;
    }
  };

  return (
    <div className="flex flex-row h-full">
      {/* Left Sidebar */}
      <div className="w-56 sm:w-56 border-r border-[color:var(--st-border)] bg-[color:var(--st-glass-bg-heavy)] backdrop-blur-[24px] flex flex-col">
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-[color:var(--st-border-subtle)]">
          <button
            onClick={onClose}
            className="h-7 w-7 rounded-lg flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-accent-dim)] transition-colors"
            title="Back"
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M10 3L5 8l5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          <span className="text-sm font-semibold text-[color:var(--st-text-primary)]">Settings</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto" role="tablist" aria-label="Settings sections">
          {NAV_ITEMS.map((item) => {
            const isActive = activeSection === item.key;
            return (
              <button
                key={item.key}
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveSection(item.key)}
                className={cn(
                  'w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer relative focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--st-accent)]/50',
                  isActive
                    ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-accent)]'
                    : 'text-[color:var(--st-text-secondary)] hover:text-[color:var(--st-text-primary)] hover:bg-[color:var(--st-accent-dim)]'
                )}
              >
                {/* Active indicator pill */}
                {isActive && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 bg-[color:var(--st-accent)] rounded-r-full" />
                )}
                <span className="shrink-0">{item.icon}</span>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-[color:var(--st-border-subtle)]">
          <span className="text-[10px] text-[color:var(--st-text-muted)] opacity-50">ShieldTier&#8482;</span>
        </div>
      </div>

      {/* Right Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-2xl mx-auto px-8 py-8">
          {renderSection()}
        </div>
      </div>
    </div>
  );
}
