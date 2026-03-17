import React, { useState, useEffect, useRef } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';

interface CaseNameModalProps {
  caseId: string;
  onSubmit: (caseName: string) => void;
  onCancel: () => void;
}

export function CaseNameModal({ caseId, onSubmit, onCancel }: CaseNameModalProps) {
  const [caseName, setCaseName] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = () => {
    const trimmed = caseName.trim();
    if (trimmed) onSubmit(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    } else if (e.key === 'Escape') {
      onCancel();
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center animate-fade-in" onClick={onCancel}>
      <div
        className="glass rounded-xl border w-[420px] max-w-[90vw] dialog-enter"
        role="dialog"
        aria-labelledby="case-modal-title"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[color:var(--st-border-subtle)]">
          <div className="flex items-center gap-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-[color:var(--st-accent)]">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
            <span id="case-modal-title" className="text-sm font-semibold text-[color:var(--st-text-primary)]">New Investigation</span>
          </div>
          <Button variant="ghost" size="icon" onClick={onCancel} className="h-7 w-7">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </Button>
        </div>

        {/* Content */}
        <div className="px-5 py-4 space-y-4">
          <p className="text-xs text-[color:var(--st-text-muted)]">
            Give this investigation a descriptive name for easy identification.
          </p>
          <div>
            <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Case ID</label>
            <div className="w-full glass-input border rounded-lg px-3 py-2 text-sm font-mono text-[color:var(--st-accent)] bg-[color:var(--st-accent-dim)] cursor-default" aria-readonly="true">
              {caseId}
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-xs text-[color:var(--st-text-muted)]">Case Name</label>
              <span className="text-[10px] text-[color:var(--st-text-muted)]">{caseName.length}/120</span>
            </div>
            <Input
              ref={inputRef}
              type="text"
              value={caseName}
              onChange={e => setCaseName(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="e.g. Phishing Campaign Q1-2026"
              maxLength={120}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-[color:var(--st-border-subtle)]">
          <Button variant="ghost" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleSubmit}
            disabled={!caseName.trim()}
          >
            Create Investigation
          </Button>
        </div>
      </div>
    </div>
  );
}
