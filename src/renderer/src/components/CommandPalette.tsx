import { Command } from 'cmdk';
import { useStore } from '../store';
import type { BottomTab, LayoutPreset } from '../store';

const NAV_ITEMS: { label: string; tab: BottomTab; shortcut: string }[] = [
  { label: 'Network Panel', tab: 'network', shortcut: '1' },
  { label: 'IOC Panel', tab: 'ioc', shortcut: '2' },
  { label: 'Screenshots', tab: 'screenshots', shortcut: '3' },
  { label: 'Files', tab: 'files', shortcut: '4' },
  { label: 'Sandbox', tab: 'sandbox', shortcut: '5' },
  { label: 'Findings', tab: 'findings', shortcut: '6' },
  { label: 'MITRE ATT&CK', tab: 'mitre', shortcut: '7' },
  { label: 'Activity', tab: 'activity', shortcut: '8' },
  { label: 'Timeline', tab: 'timeline', shortcut: '9' },
  { label: 'Process Tree', tab: 'process', shortcut: '0' },
];

const LAYOUT_ITEMS: { label: string; preset: LayoutPreset }[] = [
  { label: 'Browser Layout', preset: 'brw' },
  { label: 'Email Layout', preset: 'eml' },
  { label: 'Malware Layout', preset: 'mal' },
  { label: 'Log Layout', preset: 'log' },
];

function ShortcutBadge({ keys }: { keys: string }) {
  return (
    <span
      className="ml-auto text-[10px] font-mono tracking-wide"
      style={{ color: 'var(--st-text-muted)' }}
    >
      {keys}
    </span>
  );
}

export function CommandPalette() {
  const modalState = useStore((s) => s.modalState);
  const setModalState = useStore((s) => s.setModalState);
  const setBottomPrimaryTab = useStore((s) => s.setBottomPrimaryTab);
  const setPreset = useStore((s) => s.setPreset);

  if (modalState !== 'command') return null;

  const close = () => setModalState('none');

  const navigateTo = (tab: BottomTab) => {
    setBottomPrimaryTab(tab);
    close();
  };

  const switchLayout = (preset: LayoutPreset) => {
    setPreset(preset);
    close();
  };

  const openModal = (state: 'caseName' | 'export' | 'settings') => {
    setModalState(state);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      style={{
        background: 'rgba(0, 0, 0, 0.6)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div
        className="w-full max-w-lg rounded border overflow-hidden animate-slide-down"
        style={{
          background: 'var(--st-glass-bg-heavy)',
          backdropFilter: 'blur(var(--st-glass-blur-heavy))',
          WebkitBackdropFilter: 'blur(var(--st-glass-blur-heavy))',
          borderColor: 'var(--st-glass-border-accent)',
          boxShadow: 'var(--st-glass-shadow), 0 0 40px var(--st-accent-glow)',
        }}
      >
        <Command
          className="flex flex-col"
          label="Command Palette"
        >
          <Command.Input
            placeholder="Type a command..."
            className="w-full h-11 px-4 text-[12px] font-mono bg-transparent outline-none border-b placeholder:opacity-40"
            style={{
              color: 'var(--st-text-primary)',
              borderColor: 'var(--st-border)',
            }}
          />

          <Command.List
            className="max-h-[320px] overflow-y-auto p-1.5"
          >
            <Command.Empty
              className="py-6 text-center text-[11px]"
              style={{ color: 'var(--st-text-muted)' }}
            >
              No results found.
            </Command.Empty>

            <Command.Group
              heading="Navigation"
              className="[&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5"
              style={{ '--heading-color': 'var(--st-text-muted)' } as React.CSSProperties}
            >
              {NAV_ITEMS.map(({ label, tab, shortcut }) => (
                <Command.Item
                  key={tab}
                  value={label}
                  onSelect={() => navigateTo(tab)}
                  className="flex items-center gap-2 h-8 px-2 rounded-sm text-[11px] cursor-pointer transition-colors data-[selected=true]:bg-[var(--st-bg-hover)]"
                  style={{ color: 'var(--st-text-label)' }}
                >
                  <span className="data-[selected=true]:text-[var(--st-accent)]">{label}</span>
                  <ShortcutBadge keys={`Cmd+${shortcut}`} />
                </Command.Item>
              ))}
            </Command.Group>

            <Command.Separator className="h-px my-1" style={{ background: 'var(--st-border)' }} />

            <Command.Group
              heading="Layouts"
              className="[&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5"
            >
              {LAYOUT_ITEMS.map(({ label, preset }) => (
                <Command.Item
                  key={preset}
                  value={label}
                  onSelect={() => switchLayout(preset)}
                  className="flex items-center gap-2 h-8 px-2 rounded-sm text-[11px] cursor-pointer transition-colors data-[selected=true]:bg-[var(--st-bg-hover)]"
                  style={{ color: 'var(--st-text-label)' }}
                >
                  {label}
                </Command.Item>
              ))}
            </Command.Group>

            <Command.Separator className="h-px my-1" style={{ background: 'var(--st-border)' }} />

            <Command.Group
              heading="Session"
              className="[&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5"
            >
              <Command.Item
                value="New Case"
                onSelect={() => openModal('caseName')}
                className="flex items-center gap-2 h-8 px-2 rounded-sm text-[11px] cursor-pointer transition-colors data-[selected=true]:bg-[var(--st-bg-hover)]"
                style={{ color: 'var(--st-text-label)' }}
              >
                New Case
                <ShortcutBadge keys="Cmd+N" />
              </Command.Item>
              <Command.Item
                value="Export Report"
                onSelect={() => openModal('export')}
                className="flex items-center gap-2 h-8 px-2 rounded-sm text-[11px] cursor-pointer transition-colors data-[selected=true]:bg-[var(--st-bg-hover)]"
                style={{ color: 'var(--st-text-label)' }}
              >
                Export Report
                <ShortcutBadge keys="Cmd+E" />
              </Command.Item>
            </Command.Group>

            <Command.Separator className="h-px my-1" style={{ background: 'var(--st-border)' }} />

            <Command.Group
              heading="Settings"
              className="[&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5"
            >
              <Command.Item
                value="Settings"
                onSelect={() => openModal('settings')}
                className="flex items-center gap-2 h-8 px-2 rounded-sm text-[11px] cursor-pointer transition-colors data-[selected=true]:bg-[var(--st-bg-hover)]"
                style={{ color: 'var(--st-text-label)' }}
              >
                Settings
                <ShortcutBadge keys="Cmd+," />
              </Command.Item>
            </Command.Group>
          </Command.List>

          <div
            className="flex items-center gap-4 h-8 px-3 border-t text-[10px]"
            style={{
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-muted)',
            }}
          >
            <span>&#8593;&#8595; navigate</span>
            <span>&#8629; select</span>
            <span>&#8984;K toggle</span>
          </div>
        </Command>
      </div>
    </div>
  );
}
