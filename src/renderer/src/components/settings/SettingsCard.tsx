import React from 'react';
import { cn } from '../../lib/utils';

interface SettingsCardProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  danger?: boolean;
}

export function SettingsCard({ title, description, children, footer, danger }: SettingsCardProps) {
  return (
    <div
      className={cn(
        'glass-light rounded-xl border p-5 space-y-4',
        danger
          ? 'border-[color:var(--st-danger)]/20'
          : 'border-[color:var(--st-border-subtle)]'
      )}
    >
      <div>
        <h3 className="text-sm font-medium text-[color:var(--st-text-primary)]">{title}</h3>
        {description && (
          <p className="text-[11px] text-[color:var(--st-text-muted)] mt-0.5">{description}</p>
        )}
      </div>
      {children}
      {footer && (
        <div className="pt-3 border-t border-[color:var(--st-border-subtle)]">
          {footer}
        </div>
      )}
    </div>
  );
}
