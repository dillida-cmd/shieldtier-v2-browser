import { useEffect } from 'react';
import { useStore } from '../store';
import type { SeverityLevel } from '../ipc/types';

type ThreatLevel = 'clean' | 'suspicious' | 'malicious';

function severityToThreat(severity?: SeverityLevel): ThreatLevel {
  if (!severity) return 'clean';
  if (severity === 'critical' || severity === 'high') return 'malicious';
  if (severity === 'medium') return 'suspicious';
  return 'clean';
}

export function useThreatLevel() {
  const severity = useStore((s) => s.analysisResult?.verdict?.severity);

  useEffect(() => {
    const level = severityToThreat(severity);
    document.documentElement.setAttribute('data-threat', level);
  }, [severity]);
}
