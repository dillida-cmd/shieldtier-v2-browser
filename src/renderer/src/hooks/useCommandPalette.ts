import { useEffect, useCallback, useState } from 'react';
import type { PanelTab } from '../components/VerticalTabBar';

export interface CommandItem {
  id: string;
  label: string;
  description?: string;
  category: 'navigation' | 'session' | 'actions' | 'ioc' | 'settings';
  icon?: React.ReactNode;
  shortcut?: string;
  onSelect: () => void;
}

interface UseCommandPaletteOptions {
  /** Navigate to a panel tab */
  onNavigate?: (panel: PanelTab) => void;
  /** Create a new session */
  onNewSession?: () => void;
  /** Open settings */
  onOpenSettings?: () => void;
  /** Configure proxy */
  onConfigureProxy?: () => void;
  /** Toggle chat */
  onToggleChat?: () => void;
  /** Trigger screenshot capture */
  onCaptureScreenshot?: () => void;
  /** Export/generate report */
  onGenerateReport?: () => void;
  /** Whether a session is active */
  hasActiveSession?: boolean;
}

export function useCommandPalette(options: UseCommandPaletteOptions = {}) {
  const [open, setOpen] = useState(false);

  // Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(prev => !prev);
      }
      // Cmd+1-9 panel shortcuts
      if ((e.metaKey || e.ctrlKey) && e.key >= '1' && e.key <= '9') {
        const panelIndex = parseInt(e.key) - 1;
        const panels: PanelTab[] = ['browser', 'network', 'screenshots', 'timeline', 'analysis', 'sandbox', 'vm-sandbox', 'files', 'email'];
        if (panelIndex < panels.length && options.onNavigate) {
          e.preventDefault();
          options.onNavigate(panels[panelIndex]);
        }
      }
      // Escape closes
      if (e.key === 'Escape' && open) {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open]);

  const close = useCallback(() => setOpen(false), []);

  // Build command list
  const commands: CommandItem[] = [];

  // Navigation commands (always available if session active)
  if (options.hasActiveSession && options.onNavigate) {
    const nav = options.onNavigate;
    const panels: { id: PanelTab; label: string; shortcut?: string }[] = [
      { id: 'browser', label: 'Browser', shortcut: '1' },
      { id: 'network', label: 'Network', shortcut: '2' },
      { id: 'screenshots', label: 'Screenshots', shortcut: '3' },
      { id: 'timeline', label: 'Timeline', shortcut: '4' },
      { id: 'analysis', label: 'Analysis', shortcut: '5' },
      { id: 'sandbox', label: 'Sandbox', shortcut: '6' },
      { id: 'vm-sandbox', label: 'VM Sandbox', shortcut: '7' },
      { id: 'files', label: 'Files', shortcut: '8' },
      { id: 'email', label: 'Email', shortcut: '9' },
      { id: 'logs', label: 'Log Analysis' },
      { id: 'mitre', label: 'MITRE ATT&CK' },
      { id: 'threatfeed', label: 'Threat Feeds' },
    ];

    for (const p of panels) {
      commands.push({
        id: `nav-${p.id}`,
        label: `Go to ${p.label}`,
        category: 'navigation',
        shortcut: p.shortcut,
        onSelect: () => { nav(p.id); close(); },
      });
    }
  }

  // Session commands
  if (options.onNewSession) {
    commands.push({
      id: 'session-new',
      label: 'New Investigation',
      description: 'Create a new isolated session',
      category: 'session',
      shortcut: 'N',
      onSelect: () => { options.onNewSession!(); close(); },
    });
  }

  // Action commands
  if (options.hasActiveSession) {
    if (options.onCaptureScreenshot) {
      commands.push({
        id: 'action-screenshot',
        label: 'Capture Screenshot',
        category: 'actions',
        onSelect: () => { options.onCaptureScreenshot!(); close(); },
      });
    }
    if (options.onGenerateReport) {
      commands.push({
        id: 'action-report',
        label: 'Generate Report',
        description: 'Export investigation report',
        category: 'actions',
        onSelect: () => { options.onGenerateReport!(); close(); },
      });
    }
  }

  // Settings commands
  if (options.onOpenSettings) {
    commands.push({
      id: 'settings-open',
      label: 'Open Settings',
      category: 'settings',
      shortcut: ',',
      onSelect: () => { options.onOpenSettings!(); close(); },
    });
  }
  if (options.onConfigureProxy) {
    commands.push({
      id: 'settings-proxy',
      label: 'Configure Proxy',
      description: 'Set up network proxy',
      category: 'settings',
      onSelect: () => { options.onConfigureProxy!(); close(); },
    });
  }
  if (options.onToggleChat) {
    commands.push({
      id: 'action-chat',
      label: 'Toggle Chat',
      category: 'actions',
      onSelect: () => { options.onToggleChat!(); close(); },
    });
  }

  return { open, setOpen, close, commands };
}
