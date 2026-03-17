import React, { useState, useEffect } from 'react';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import { SettingsCard } from './SettingsCard';
import { SettingsRow } from './SettingsRow';

// ═══════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════

type ThemeOption = 'dark' | 'light' | 'system';
type FontFamily = 'inter' | 'system';
type FontSize = 'small' | 'default' | 'large';

interface UIPrefs {
  theme: ThemeOption;
  fontFamily: FontFamily;
  fontSize: FontSize;
  language: string;
}

const DEFAULT_PREFS: UIPrefs = {
  theme: 'dark',
  fontFamily: 'inter',
  fontSize: 'default',
  language: 'en',
};

// ═══════════════════════════════════════════════════════
// Theme Preview Cards — mini UI mockups
// ═══════════════════════════════════════════════════════

function ThemePreview({ variant }: { variant: ThemeOption }) {
  const isDark = variant === 'dark';
  const isSystem = variant === 'system';

  const bg = isDark ? '#0a0e17' : isSystem ? '#0a0e17' : '#e8ecf1';
  const sidebar = isDark ? '#111827' : isSystem ? '#111827' : '#dfe3ea';
  const card = isDark ? '#1a2332' : isSystem ? '#1a2332' : '#ffffff';
  const text = isDark ? '#94a3b8' : isSystem ? '#94a3b8' : '#444444';
  const textBright = isDark ? '#f1f5f9' : isSystem ? '#f1f5f9' : '#1b1b1b';
  const accent = isDark ? '#3b82f6' : '#2672ec';
  const border = isDark ? '#1e293b' : isSystem ? '#1e293b' : '#b8bcc4';

  return (
    <svg width="100%" height="64" viewBox="0 0 120 64" fill="none" className="rounded-md overflow-hidden">
      <rect width="120" height="64" fill={bg} />
      <rect width="28" height="64" fill={sidebar} />
      <rect x="28" y="0" width="0.5" height="64" fill={border} />
      <rect x="5" y="8" width="18" height="3" rx="1" fill={accent} opacity="0.25" />
      <rect x="5" y="14" width="14" height="2" rx="1" fill={text} opacity="0.4" />
      <rect x="5" y="19" width="16" height="2" rx="1" fill={text} opacity="0.3" />
      <rect x="5" y="24" width="12" height="2" rx="1" fill={text} opacity="0.3" />
      <rect x="28" y="0" width="92" height="10" fill={sidebar} />
      <rect x="28" y="10" width="92" height="0.5" fill={border} />
      <rect x="34" y="16" width="80" height="18" rx="3" fill={card} stroke={border} strokeWidth="0.5" />
      <rect x="38" y="20" width="30" height="2.5" rx="1" fill={textBright} opacity="0.7" />
      <rect x="38" y="25" width="50" height="2" rx="1" fill={text} opacity="0.4" />
      <rect x="38" y="29" width="20" height="2" rx="1" fill={text} opacity="0.3" />
      <rect x="34" y="38" width="80" height="18" rx="3" fill={card} stroke={border} strokeWidth="0.5" />
      <rect x="38" y="42" width="24" height="2.5" rx="1" fill={textBright} opacity="0.7" />
      <rect x="38" y="47" width="40" height="2" rx="1" fill={text} opacity="0.4" />
      <rect x="38" y="51" width="16" height="2" rx="1" fill={text} opacity="0.3" />
      <rect x="2" y="8" width="1.5" height="3" rx="0.75" fill={accent} />
      {isSystem && (
        <>
          <clipPath id="system-light-half">
            <polygon points="120,0 120,64 40,64" />
          </clipPath>
          <g clipPath="url(#system-light-half)">
            <rect width="120" height="64" fill="#e8ecf1" />
            <rect width="28" height="64" fill="#dfe3ea" />
            <rect x="28" y="0" width="0.5" height="64" fill="#b8bcc4" />
            <rect x="28" y="0" width="92" height="10" fill="#dfe3ea" />
            <rect x="28" y="10" width="92" height="0.5" fill="#b8bcc4" />
            <rect x="34" y="16" width="80" height="18" rx="2" fill="#ffffff" stroke="#b8bcc4" strokeWidth="0.5" />
            <rect x="38" y="20" width="30" height="2.5" rx="1" fill="#1b1b1b" opacity="0.7" />
            <rect x="38" y="25" width="50" height="2" rx="1" fill="#444444" opacity="0.5" />
            <rect x="34" y="38" width="80" height="18" rx="2" fill="#ffffff" stroke="#b8bcc4" strokeWidth="0.5" />
            <rect x="38" y="42" width="24" height="2.5" rx="1" fill="#1b1b1b" opacity="0.7" />
            <rect x="38" y="47" width="40" height="2" rx="1" fill="#444444" opacity="0.5" />
          </g>
          <line x1="120" y1="0" x2="40" y2="64" stroke="rgba(148,163,184,0.3)" strokeWidth="0.5" />
        </>
      )}
    </svg>
  );
}

// ═══════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════

const THEME_OPTIONS: { value: ThemeOption; label: string; description: string }[] = [
  { value: 'dark', label: 'Dark', description: 'Tactical dark interface' },
  { value: 'light', label: 'Light', description: 'Clean Aero-inspired interface' },
  { value: 'system', label: 'System', description: 'Follows OS preference' },
];

const FONT_FAMILY_OPTIONS: { value: FontFamily; label: string; description: string }[] = [
  { value: 'inter', label: 'Inter', description: 'Optimized for UI' },
  { value: 'system', label: 'System Default', description: 'Native OS font stack' },
];

const FONT_SIZE_OPTIONS: { value: FontSize; label: string; px: number }[] = [
  { value: 'small', label: 'S', px: 13 },
  { value: 'default', label: 'M', px: 14 },
  { value: 'large', label: 'L', px: 16 },
];

// ═══════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════

function applyTheme(theme: ThemeOption) {
  document.documentElement.setAttribute('data-theme', theme);
}

function applyFontSize(size: FontSize) {
  const px = FONT_SIZE_OPTIONS.find(o => o.value === size)?.px ?? 14;
  document.documentElement.style.setProperty('--st-font-size-base', `${px}px`);
}

function applyFontFamily(family: FontFamily) {
  if (family === 'system') {
    document.documentElement.style.setProperty(
      '--font-sans',
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    );
  } else {
    document.documentElement.style.setProperty(
      '--font-sans',
      "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    );
  }
}

// ═══════════════════════════════════════════════════════
// Chevron icon for selects
// ═══════════════════════════════════════════════════════

function ChevronDown() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="pointer-events-none text-[color:var(--st-text-muted)]">
      <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ═══════════════════════════════════════════════════════
// AppearanceSection
// ═══════════════════════════════════════════════════════

export function AppearanceSection() {
  const [prefs, setPrefs] = useState<UIPrefs>(DEFAULT_PREFS);
  const [savedPrefs, setSavedPrefs] = useState<UIPrefs>(DEFAULT_PREFS);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const saved = await window.shieldtier.config.get('ui');
        if (saved) {
          const merged = { ...DEFAULT_PREFS, ...saved };
          setPrefs(merged);
          setSavedPrefs(merged);
        }
      } catch {}
      setLoaded(true);
    })();
  }, []);

  const isDirty = loaded && (
    prefs.theme !== savedPrefs.theme ||
    prefs.fontFamily !== savedPrefs.fontFamily ||
    prefs.fontSize !== savedPrefs.fontSize ||
    prefs.language !== savedPrefs.language
  );

  useEffect(() => {
    if (!loaded) return;
    applyTheme(prefs.theme);
    applyFontSize(prefs.fontSize);
    applyFontFamily(prefs.fontFamily);
  }, [prefs.theme, prefs.fontSize, prefs.fontFamily, loaded]);

  const handleSave = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const result = await window.shieldtier.config.set('ui', prefs);
      if (result.success) {
        setSavedPrefs({ ...prefs });
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

  if (!loaded) return null;

  return (
    <div className="space-y-4">
      {/* Page header */}
      <div className="mb-2">
        <h2 className="text-base font-semibold text-[color:var(--st-text-primary)]">Appearance</h2>
        <p className="text-xs text-[color:var(--st-text-muted)] mt-1">Customize how ShieldTier looks and feels.</p>
      </div>

      {/* ── Card 1: Theme ── */}
      <SettingsCard title="Theme">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3" role="radiogroup" aria-label="Theme">
          {THEME_OPTIONS.map((opt) => {
            const selected = prefs.theme === opt.value;
            return (
              <button
                key={opt.value}
                role="radio"
                aria-checked={selected}
                onClick={() => setPrefs(p => ({ ...p, theme: opt.value }))}
                className={cn(
                  'group relative flex flex-col rounded-xl border overflow-hidden transition-all duration-200 cursor-pointer',
                  selected
                    ? 'border-[color:var(--st-accent)]/60 ring-2 ring-[color:var(--st-accent)]/20'
                    : 'border-[color:var(--st-border)] hover:border-[color:var(--st-text-muted)] hover:shadow-lg'
                )}
              >
                <div className="p-2 pb-0">
                  <ThemePreview variant={opt.value} />
                </div>
                <div className={cn(
                  'flex items-center justify-between px-3 py-2.5 transition-colors',
                  selected
                    ? 'bg-blue-500/10'
                    : 'bg-transparent group-hover:bg-[color:var(--st-accent-dim)]'
                )}>
                  <div>
                    <span className={cn(
                      'text-xs font-medium block',
                      selected ? 'text-blue-400' : 'text-[color:var(--st-text-primary)]'
                    )}>
                      {opt.label}
                    </span>
                    <span className="text-[10px] text-[color:var(--st-text-muted)] leading-none">{opt.description}</span>
                  </div>
                  {selected && (
                    <div className="w-4 h-4 rounded-full bg-blue-500 flex items-center justify-center shrink-0">
                      <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
                        <path d="M1.5 4L3.5 6L6.5 2" stroke="white" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </div>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </SettingsCard>

      {/* ── Card 2: Typography ── */}
      <SettingsCard title="Typography">
        {/* Font Family */}
        <SettingsRow label="Font Family" description="Choose the typeface for the interface.">
          <div className="flex gap-2">
            {FONT_FAMILY_OPTIONS.map((opt) => {
              const selected = prefs.fontFamily === opt.value;
              return (
                <button
                  key={opt.value}
                  role="radio"
                  aria-checked={selected}
                  onClick={() => setPrefs(p => ({ ...p, fontFamily: opt.value }))}
                  className={cn(
                    'flex items-center gap-2 px-3 py-2 rounded-lg border transition-all cursor-pointer text-left',
                    selected
                      ? 'border-blue-500/50 bg-blue-500/8 ring-1 ring-blue-500/15'
                      : 'border-[color:var(--st-border)] hover:border-[color:var(--st-text-muted)] hover:bg-[color:var(--st-accent-dim)]'
                  )}
                >
                  <span className={cn(
                    'text-sm font-semibold shrink-0',
                    selected ? 'text-blue-400' : 'text-[color:var(--st-text-primary)]',
                    opt.value === 'inter' ? "font-['Inter']" : 'font-sans'
                  )}>
                    Aa
                  </span>
                  <span className={cn(
                    'text-[11px] font-medium',
                    selected ? 'text-blue-400' : 'text-[color:var(--st-text-primary)]'
                  )}>
                    {opt.label}
                  </span>
                </button>
              );
            })}
          </div>
        </SettingsRow>

        {/* Font Size — segmented control */}
        <SettingsRow label="Interface Size" description="Adjust the base font size.">
          <div className="inline-flex items-center rounded-lg border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)] p-0.5" role="radiogroup" aria-label="Interface size">
            {FONT_SIZE_OPTIONS.map((opt) => {
              const selected = prefs.fontSize === opt.value;
              return (
                <button
                  key={opt.value}
                  role="radio"
                  aria-checked={selected}
                  onClick={() => setPrefs(p => ({ ...p, fontSize: opt.value }))}
                  className={cn(
                    'relative px-5 py-1.5 text-xs font-medium rounded-md transition-all duration-200 cursor-pointer',
                    selected
                      ? 'bg-[color:var(--st-bg-elevated)] text-[color:var(--st-text-primary)] shadow-sm'
                      : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)]'
                  )}
                >
                  <span className="relative z-10">{opt.label}</span>
                  <span className={cn(
                    'ml-1 text-[10px] relative z-10 tabular-nums',
                    selected ? 'opacity-50' : 'opacity-40'
                  )}>
                    {opt.px}
                  </span>
                </button>
              );
            })}
          </div>
        </SettingsRow>
      </SettingsCard>

      {/* ── Card 3: Language ── */}
      <SettingsCard title="Language">
        <SettingsRow label="Display Language" description="More languages coming soon.">
          <div className="relative inline-block">
            <select
              id="language-select"
              value={prefs.language}
              onChange={(e) => setPrefs(p => ({ ...p, language: e.target.value }))}
              className="appearance-none border border-[color:var(--st-border)] bg-[color:var(--st-bg-panel)] rounded-lg pl-3 pr-8 py-2 text-xs text-[color:var(--st-text-primary)] cursor-pointer focus:outline-none focus:ring-1 focus:ring-[color:var(--st-accent)]/40 focus:border-[color:var(--st-accent)]/40 transition-colors"
            >
              <option value="en">English</option>
            </select>
            <div className="absolute right-2.5 top-1/2 -translate-y-1/2">
              <ChevronDown />
            </div>
          </div>
        </SettingsRow>
      </SettingsCard>

      {/* ── Save Bar ── */}
      <div className="flex items-center gap-3 pt-2">
        <Button
          size="sm"
          onClick={handleSave}
          disabled={saving || !isDirty}
          className={cn(
            'transition-all duration-200',
            isDirty && 'shadow-md shadow-blue-500/20'
          )}
        >
          {saving ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-3 w-3" viewBox="0 0 12 12" fill="none">
                <circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.5" opacity="0.25" />
                <path d="M11 6a5 5 0 00-5-5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
              Saving
            </span>
          ) : 'Save Changes'}
        </Button>
        {isDirty && !msg && (
          <span className="text-[10px] text-[color:var(--st-text-muted)] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            Unsaved changes
          </span>
        )}
        {msg && (
          <span
            role={msg.type === 'success' ? 'status' : 'alert'}
            aria-live={msg.type === 'success' ? 'polite' : undefined}
            className={cn(
              'text-xs flex items-center gap-1.5 transition-opacity',
              msg.type === 'success' ? 'text-green-400' : 'text-red-400'
            )}
          >
            {msg.type === 'success' && (
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M2.5 6.5L5 9L9.5 3.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
            {msg.text}
          </span>
        )}
      </div>
    </div>
  );
}
