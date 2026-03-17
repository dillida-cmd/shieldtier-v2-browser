import React, { useMemo } from 'react';
import { Command } from 'cmdk';
import type { CommandItem } from '../hooks/useCommandPalette';

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: CommandItem[];
}

const CATEGORY_LABELS: Record<string, string> = {
  navigation: 'Navigation',
  session: 'Session',
  actions: 'Actions',
  ioc: 'IOC Lookup',
  settings: 'Settings',
};

const CATEGORY_ORDER = ['navigation', 'session', 'actions', 'ioc', 'settings'];

export function CommandPalette({ open, onOpenChange, commands }: CommandPaletteProps) {
  const grouped = useMemo(() => {
    const groups: Record<string, CommandItem[]> = {};
    for (const cmd of commands) {
      if (!groups[cmd.category]) groups[cmd.category] = [];
      groups[cmd.category].push(cmd);
    }
    return groups;
  }, [commands]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[20vh]"
      onClick={() => onOpenChange(false)}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />

      {/* Palette */}
      <div
        className="relative glass rounded-xl border border-[color:var(--st-glass-border)] w-[560px] max-w-[90vw] shadow-2xl animate-fade-in overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <Command
          label="Command Palette"
          className="flex flex-col"
        >
          {/* Search input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/8">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-[color:var(--st-text-muted)] shrink-0">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <Command.Input
              placeholder="Type a command or search..."
              aria-label="Search commands"
              className="flex-1 bg-transparent text-sm text-[color:var(--st-text-primary)] placeholder:text-[color:var(--st-text-muted)] outline-none"
              autoFocus
            />
            <kbd className="text-[10px] text-[color:var(--st-text-muted)] bg-white/5 rounded px-1.5 py-0.5 border border-white/10 font-mono">
              ESC
            </kbd>
          </div>

          {/* Command list */}
          <Command.List className="max-h-[320px] overflow-y-auto p-2">
            <Command.Empty className="py-6 text-center text-sm text-[color:var(--st-text-muted)]">
              No commands found.
            </Command.Empty>

            {CATEGORY_ORDER.map(cat => {
              const items = grouped[cat];
              if (!items || items.length === 0) return null;
              return (
                <Command.Group
                  key={cat}
                  heading={CATEGORY_LABELS[cat] || cat}
                  className="mb-2"
                >
                  <div className="text-[10px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider px-2 py-1.5">
                    {CATEGORY_LABELS[cat] || cat}
                  </div>
                  {items.map(cmd => (
                    <Command.Item
                      key={cmd.id}
                      value={`${cmd.label} ${cmd.description || ''}`}
                      onSelect={cmd.onSelect}
                      className="flex items-center justify-between gap-2 px-2 py-1.5 text-sm rounded-md cursor-pointer text-[color:var(--st-text-secondary)] data-[selected=true]:bg-[color:var(--st-accent-dim)] data-[selected=true]:text-[color:var(--st-text-primary)] transition-colors"
                    >
                      <div className="flex-1 min-w-0">
                        <span className="text-[color:var(--st-text-primary)]">{cmd.label}</span>
                        {cmd.description && (
                          <span className="text-[color:var(--st-text-muted)] text-xs ml-2">{cmd.description}</span>
                        )}
                      </div>
                      {cmd.shortcut && (
                        <kbd className="text-[10px] text-[color:var(--st-text-muted)] bg-white/5 rounded px-1.5 py-0.5 border border-white/10 font-mono shrink-0">
                          {cmd.shortcut}
                        </kbd>
                      )}
                    </Command.Item>
                  ))}
                </Command.Group>
              );
            })}
          </Command.List>

          {/* Footer hint */}
          <div className="flex items-center justify-between px-4 py-2 border-t border-white/8 text-[10px] text-[color:var(--st-text-muted)]">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <kbd className="bg-white/5 rounded px-1 py-0.5 border border-white/10 font-mono">↑↓</kbd>
                navigate
              </span>
              <span className="flex items-center gap-1">
                <kbd className="bg-white/5 rounded px-1 py-0.5 border border-white/10 font-mono">↵</kbd>
                select
              </span>
            </div>
            <span className="flex items-center gap-1">
              <kbd className="bg-white/5 rounded px-1 py-0.5 border border-white/10 font-mono">⌘K</kbd>
              <span className="hidden" aria-hidden="true">/</span>
              <kbd className="bg-white/5 rounded px-1 py-0.5 border border-white/10 font-mono">Ctrl+K</kbd>
              toggle
            </span>
          </div>
        </Command>
      </div>
    </div>
  );
}
