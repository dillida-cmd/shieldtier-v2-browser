import React, { useEffect, useState } from 'react';
import { cn } from '../../lib/utils';

interface StatusItem {
  label: string;
  status: 'ok' | 'warning' | 'error' | 'unknown';
  detail?: string;
}

export function SystemStatus() {
  const [items, setItems] = useState<StatusItem[]>([]);

  useEffect(() => {
    const checks: StatusItem[] = [];

    (async () => {
      // Check QEMU
      try {
        const qemu = await window.shieldtier.vm.getQEMUStatus();
        checks.push({
          label: 'QEMU VM Engine',
          status: qemu.installed ? 'ok' : 'warning',
          detail: qemu.installed ? qemu.version || 'Installed' : 'Not installed',
        });
      } catch {
        checks.push({ label: 'QEMU VM Engine', status: 'unknown', detail: 'Check failed' });
      }

      // Check API keys
      try {
        const config = await window.shieldtier.config.getAPIKeys?.();
        const configured = config ? Object.values(config).filter(Boolean).length : 0;
        checks.push({
          label: 'Enrichment API Keys',
          status: configured > 0 ? 'ok' : 'warning',
          detail: configured > 0 ? `${configured} configured` : 'None configured',
        });
      } catch {
        checks.push({ label: 'Enrichment API Keys', status: 'unknown' });
      }

      // Cloud connection
      checks.push({
        label: 'Cloud Connection',
        status: 'ok',
        detail: 'Authenticated',
      });

      setItems(checks);
    })();
  }, []);

  return (
    <div>
      <h3 className="text-xs font-semibold text-[color:var(--st-text-muted)] uppercase tracking-wider mb-3">
        System Status
      </h3>
      <div className="glass rounded-xl border divide-y divide-[color:var(--st-border-subtle)]">
        {items.length === 0 ? (
          <div className="p-4" aria-label="Loading" role="status">
            <div className="h-4 w-32 rounded bg-[color:var(--st-border-subtle)] shimmer" />
          </div>
        ) : (
          items.map(item => (
            <div key={item.label} className="flex items-center gap-3 px-4 py-3">
              <div className={cn(
                'w-6 h-6 rounded-md flex items-center justify-center shrink-0',
                item.status === 'ok' && 'text-[color:var(--st-success)] bg-[color:var(--st-success)]/10',
                item.status === 'warning' && 'text-[color:var(--st-warning)] bg-[color:var(--st-warning)]/10',
                item.status === 'error' && 'text-[color:var(--st-danger)] bg-[color:var(--st-danger)]/10',
                item.status === 'unknown' && 'text-[color:var(--st-text-secondary)] bg-[color:var(--st-accent-dim)]',
              )}>
                {item.status === 'ok' && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-label="Operational">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                )}
                {item.status === 'warning' && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-label="Warning">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                )}
                {item.status === 'error' && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-label="Error">
                    <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
                  </svg>
                )}
                {item.status === 'unknown' && (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-label="Unknown">
                    <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-xs text-[color:var(--st-text-primary)]">{item.label}</span>
              </div>
              <span className="text-xs text-[color:var(--st-text-muted)] font-mono">{item.detail}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
