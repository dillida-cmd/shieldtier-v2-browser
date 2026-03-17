import React from 'react';

interface SettingsRowProps {
  label: string;
  description?: string;
  children: React.ReactNode;
}

export function SettingsRow({ label, description, children }: SettingsRowProps) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <span className="text-xs font-medium text-[color:var(--st-text-primary)]">{label}</span>
        {description && (
          <p className="text-[11px] text-[color:var(--st-text-muted)] mt-0.5">{description}</p>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}
