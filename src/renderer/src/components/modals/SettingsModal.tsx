import { useState, useEffect } from 'react';
import { useStore } from '../../store';
import type { ThemeMode, FontSize } from '../../store';
import { ipcCall } from '../../ipc/bridge';
import { AppearanceSection } from '../settings/AppearanceSection';
import { GeneralSection } from '../settings/GeneralSection';
import { NetworkSection } from '../settings/NetworkSection';
import { AboutSection } from '../settings/AboutSection';

type SettingsTab = 'appearance' | 'general' | 'network' | 'about';

const TABS: { value: SettingsTab; label: string }[] = [
  { value: 'appearance', label: 'Appearance' },
  { value: 'general', label: 'General' },
  { value: 'network', label: 'Network' },
  { value: 'about', label: 'About' },
];

export function SettingsModal() {
  const modalState = useStore((s) => s.modalState);
  const setModalState = useStore((s) => s.setModalState);
  const storeTheme = useStore((s) => s.theme);
  const storeFontSize = useStore((s) => s.fontSize);
  const setTheme = useStore((s) => s.setTheme);
  const setFontSize = useStore((s) => s.setFontSize);

  const [activeTab, setActiveTab] = useState<SettingsTab>('appearance');

  useEffect(() => {
    if (modalState !== 'settings') return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setModalState('none');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [modalState, setModalState]);

  if (modalState !== 'settings') return null;

  const handleThemeChange = (t: ThemeMode) => {
    setTheme(t);
    document.documentElement.setAttribute('data-theme', t);
    ipcCall('set_config', { key: 'ui', value: { theme: t, fontSize: storeFontSize } });
  };

  const handleFontSizeChange = (s: FontSize) => {
    setFontSize(s);
    document.documentElement.setAttribute('data-font', s);
    ipcCall('set_config', { key: 'ui', value: { theme: storeTheme, fontSize: s } });
  };

  const close = () => setModalState('none');

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'var(--st-bg-overlay)', backdropFilter: 'blur(6px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) close(); }}
    >
      <div
        className="glass-heavy border rounded w-full max-w-2xl animate-slide-up overflow-hidden"
        style={{ borderColor: 'var(--st-border)', maxHeight: '70vh' }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--st-border)' }}>
          <span className="text-[var(--st-text-label)] text-sm font-bold tracking-wider uppercase">Settings</span>
          <button
            onClick={close}
            className="text-[var(--st-text-muted)] hover:text-[var(--st-text-primary)] text-lg leading-none transition-colors"
          >
            &times;
          </button>
        </div>

        <div className="flex" style={{ minHeight: '340px' }}>
          <nav className="w-40 flex-shrink-0 border-r p-2 flex flex-col gap-0.5" style={{ borderColor: 'var(--st-border)' }}>
            {TABS.map((tab) => (
              <button
                key={tab.value}
                onClick={() => setActiveTab(tab.value)}
                className="text-left px-3 py-2 rounded text-[11px] transition-colors"
                style={{
                  background: activeTab === tab.value ? 'var(--st-bg-hover)' : 'transparent',
                  color: activeTab === tab.value ? 'var(--st-text-primary)' : 'var(--st-text-label)',
                  fontWeight: activeTab === tab.value ? 700 : 400,
                }}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="flex-1 p-5 overflow-y-auto">
            {activeTab === 'appearance' && (
              <AppearanceSection
                theme={storeTheme}
                fontSize={storeFontSize}
                onThemeChange={handleThemeChange}
                onFontSizeChange={handleFontSizeChange}
              />
            )}
            {activeTab === 'general' && <GeneralSection />}
            {activeTab === 'network' && <NetworkSection />}
            {activeTab === 'about' && <AboutSection />}
          </div>
        </div>
      </div>
    </div>
  );
}
