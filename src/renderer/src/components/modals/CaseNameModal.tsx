import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';

function generateCaseId(): string {
  const tsHex = Date.now().toString(16).slice(-6);
  const rand = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0');
  return `ST-${tsHex}-${rand}`.toUpperCase();
}

export function CaseNameModal() {
  const modalState = useStore((s) => s.modalState);
  const setModalState = useStore((s) => s.setModalState);
  const setCaseInfo = useStore((s) => s.setCaseInfo);

  const [name, setName] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const caseId = useMemo(() => generateCaseId(), []);

  const isOpen = modalState === 'caseName';

  const close = useCallback(() => {
    setName('');
    setModalState('none');
  }, [setModalState]);

  const submit = useCallback(async () => {
    const trimmed = name.trim();
    if (!trimmed) return;

    await ipcCall('set_config', { key: 'case', value: { id: caseId, name: trimmed } });
    setCaseInfo(caseId, trimmed);
    setName('');
    setModalState('none');
  }, [name, caseId, setCaseInfo, setModalState]);

  useEffect(() => {
    if (!isOpen) return;

    const raf = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(raf);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        close();
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        submit();
      }
    }

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close, submit]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'var(--st-bg-overlay)', backdropFilter: 'blur(6px)', WebkitBackdropFilter: 'blur(6px)' }}
      onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}
    >
      <div
        className="w-full max-w-md glass-heavy border border-[var(--st-border)] rounded p-6 animate-slide-up"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h2
          className="text-sm font-bold uppercase tracking-wider mb-5"
          style={{ color: 'var(--st-text-label)' }}
        >
          NEW CASE
        </h2>

        <div className="mb-4">
          <label
            className="block mb-1 uppercase tracking-wider font-medium"
            style={{ fontSize: '10px', color: 'var(--st-text-muted)' }}
          >
            CASE ID
          </label>
          <div
            className="font-mono rounded px-3 py-2 border select-all"
            style={{
              color: 'var(--st-accent)',
              background: 'var(--st-glass-input-bg)',
              borderColor: 'var(--st-border)',
              fontSize: '12px',
            }}
          >
            {caseId}
          </div>
        </div>

        <div className="mb-6">
          <label
            className="block mb-1 uppercase tracking-wider font-medium"
            style={{ fontSize: '10px', color: 'var(--st-text-muted)' }}
          >
            CASE NAME
          </label>
          <input
            ref={inputRef}
            type="text"
            maxLength={120}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Enter case name..."
            className="w-full rounded px-3 py-2 border outline-none transition-colors"
            style={{
              background: 'var(--st-glass-input-bg)',
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-primary)',
              fontSize: '12px',
              fontFamily: 'var(--st-font-mono)',
            }}
            onFocus={(e) => { (e.target as HTMLInputElement).style.borderColor = 'var(--st-glass-border-accent)'; }}
            onBlur={(e) => { (e.target as HTMLInputElement).style.borderColor = 'var(--st-border)'; }}
          />
        </div>

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={close}
            className="px-4 py-1.5 rounded border text-xs cursor-pointer transition-colors"
            style={{
              background: 'transparent',
              borderColor: 'var(--st-border)',
              color: 'var(--st-text-label)',
            }}
            onMouseEnter={(e) => { (e.target as HTMLElement).style.background = 'var(--st-bg-hover)'; }}
            onMouseLeave={(e) => { (e.target as HTMLElement).style.background = 'transparent'; }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={!name.trim()}
            className="px-4 py-1.5 rounded text-xs font-bold cursor-pointer transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
            style={{
              background: 'var(--st-accent)',
              color: 'var(--st-bg-primary)',
            }}
            onMouseEnter={(e) => { if (name.trim()) (e.target as HTMLElement).style.opacity = '0.9'; }}
            onMouseLeave={(e) => { (e.target as HTMLElement).style.opacity = '1'; }}
          >
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
