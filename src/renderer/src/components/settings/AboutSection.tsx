export function AboutSection() {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded bg-[var(--st-accent)] flex items-center justify-center flex-shrink-0">
          <span className="text-[var(--st-bg-primary)] text-lg font-black">S</span>
        </div>
        <div>
          <div className="text-[var(--st-text-primary)] text-[13px] font-bold">ShieldTier V2</div>
          <div className="text-[var(--st-text-muted)] text-[10px] font-mono">v2.0.0-alpha</div>
        </div>
      </div>

      <div className="h-px bg-[var(--st-border)]" />

      <div className="flex flex-col gap-2">
        <Row label="Engine" value="CEF (Chromium Embedded)" />
        <Row label="Analysis" value="Native C++ / libyara" />
        <Row label="Crypto" value="libsodium + BoringSSL" />
        <Row label="Sandbox" value="QEMU VM + Inline CEF" />
      </div>

      <div className="h-px bg-[var(--st-border)]" />

      <p className="text-[10px] text-[var(--st-text-muted)] leading-relaxed">
        SOC malware analysis browser. Built for threat intelligence, incident response, and malware triage.
      </p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-[10px] text-[var(--st-text-muted)] uppercase tracking-wider">{label}</span>
      <span className="text-[11px] text-[var(--st-text-label)] font-mono">{value}</span>
    </div>
  );
}
