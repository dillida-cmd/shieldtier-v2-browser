import { useState } from 'react';

interface ProxyConfig {
  host: string;
  port: string;
  username: string;
  password: string;
}

export function NetworkSection() {
  const [proxy, setProxy] = useState<ProxyConfig>({ host: '', port: '', username: '', password: '' });

  const inputStyle: React.CSSProperties = {
    background: 'var(--st-glass-input-bg)',
    border: '1px solid var(--st-border)',
    color: 'var(--st-text-primary)',
    borderRadius: 'var(--st-radius)',
    padding: '6px 10px',
    fontSize: '11px',
    fontFamily: 'var(--st-font-mono)',
    width: '100%',
    outline: 'none',
  };

  return (
    <div className="flex flex-col gap-4">
      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-1.5 block">
          Proxy Host
        </label>
        <input
          style={inputStyle}
          value={proxy.host}
          onChange={(e) => setProxy((p) => ({ ...p, host: e.target.value }))}
          placeholder="e.g. 127.0.0.1"
        />
      </div>
      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-1.5 block">
          Proxy Port
        </label>
        <input
          style={inputStyle}
          value={proxy.port}
          onChange={(e) => setProxy((p) => ({ ...p, port: e.target.value }))}
          placeholder="e.g. 8080"
        />
      </div>
      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-1.5 block">
          Username
        </label>
        <input
          style={inputStyle}
          value={proxy.username}
          onChange={(e) => setProxy((p) => ({ ...p, username: e.target.value }))}
          placeholder="Optional"
        />
      </div>
      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-1.5 block">
          Password
        </label>
        <input
          style={inputStyle}
          type="password"
          value={proxy.password}
          onChange={(e) => setProxy((p) => ({ ...p, password: e.target.value }))}
          placeholder="Optional"
        />
      </div>
    </div>
  );
}
