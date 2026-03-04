import { useMemo } from 'react';
import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { useStore, type LayoutPreset } from '../../store';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/Tooltip';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
} from '../ui/DropdownMenu';

const PRESETS: Array<{ id: LayoutPreset; label: string; desc: string }> = [
  { id: 'brw', label: 'BRW', desc: 'Browser + Network analysis' },
  { id: 'eml', label: 'EML', desc: 'Email + Findings analysis' },
  { id: 'mal', label: 'MAL', desc: 'Malware sandbox analysis' },
  { id: 'log', label: 'LOG', desc: 'Logs + Timeline analysis' },
];

const FEED_PROVIDERS = ['VirusTotal', 'AbuseIPDB', 'OTX AlienVault', 'URLhaus', 'MalwareBazaar'];

export function IconRail() {
  const { preset, setPreset, capturing, analysisResult, vmFindings } = useStore();

  const yaraCount = useMemo(() => {
    const findings = analysisResult?.verdict?.findings ?? [];
    return findings.filter((f) => f.engine === 'yara').length;
  }, [analysisResult]);

  const yaraMatches = useMemo(() => {
    const findings = analysisResult?.verdict?.findings ?? [];
    return findings.filter((f) => f.engine === 'yara').slice(0, 5);
  }, [analysisResult]);

  return (
    <div className="glass-heavy w-[52px] border-r border-[var(--st-border)] flex flex-col items-center py-2 flex-shrink-0 gap-1">
      {PRESETS.map((p) => (
        <Tooltip key={p.id}>
          <TooltipTrigger asChild>
            <button
              onClick={() => setPreset(p.id)}
              className={cn(
                'w-10 h-9 rounded-lg border-none flex flex-col items-center justify-center cursor-pointer transition-colors text-[10px] font-bold tracking-wider',
                preset === p.id
                  ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)] glow-accent border-l-2 border-l-[var(--st-accent)]'
                  : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)]',
              )}
            >
              {p.label}
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">{p.desc}</TooltipContent>
        </Tooltip>
      ))}

      <div className="w-7 h-px bg-[var(--st-border)] my-1" />

      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2L2 7l10 5 10-5-10-5z" />
                  <path d="M2 17l10 5 10-5" />
                  <path d="M2 12l10 5 10-5" />
                </svg>
                <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">YARA</span>
                <div className="absolute -top-0.5 -right-0.5">
                  <CountBadge count={yaraCount} color="purple" />
                </div>
              </button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="right">YARA rule matches</TooltipContent>
        </Tooltip>
        <DropdownMenuContent side="right" align="start">
          <DropdownMenuLabel>YARA Matches ({yaraCount})</DropdownMenuLabel>
          {yaraMatches.length === 0 ? (
            <DropdownMenuItem disabled>No matches</DropdownMenuItem>
          ) : (
            yaraMatches.map((m, i) => (
              <DropdownMenuItem key={i}>
                <span className="text-[var(--st-severity-critical)]">{m.severity[0].toUpperCase()}</span>
                <span className="truncate">{m.title}</span>
              </DropdownMenuItem>
            ))
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 2a10 10 0 0 1 0 20" />
                  <path d="M2 12h20" />
                </svg>
                <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">FEED</span>
              </button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="right">Threat intelligence feeds</TooltipContent>
        </Tooltip>
        <DropdownMenuContent side="right" align="start">
          <DropdownMenuLabel>Threat Feeds</DropdownMenuLabel>
          {FEED_PROVIDERS.map((provider) => (
            <DropdownMenuItem key={provider}>{provider}</DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      <div className="flex-1" />

      <Tooltip>
        <TooltipTrigger asChild>
          <div className="flex flex-col items-center gap-0.5 mb-1">
            <StatusDot status={capturing ? 'recording' : 'idle'} />
            <span className={cn(
              'text-[7px] font-bold uppercase tracking-wider',
              capturing ? 'text-[var(--st-severity-critical)]' : 'text-[var(--st-text-muted)]',
            )}>
              REC
            </span>
          </div>
        </TooltipTrigger>
        <TooltipContent side="right">{capturing ? 'Recording network traffic' : 'Capture idle'}</TooltipContent>
      </Tooltip>
    </div>
  );
}
