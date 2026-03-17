import React, { createContext, useContext, useMemo, useEffect } from 'react';
import type { Verdict, FileRiskLevel, PhishingVerdict } from '../types';

export type ThreatLevel = 'clean' | 'suspicious' | 'malicious';

interface ThreatLevelContextValue {
  threatLevel: ThreatLevel;
}

const ThreatLevelContext = createContext<ThreatLevelContextValue>({ threatLevel: 'clean' });

export function useThreatLevel() {
  return useContext(ThreatLevelContext);
}

interface ThreatSignals {
  /** IOC enrichment verdicts for the active session */
  iocVerdicts?: Verdict[];
  /** File risk levels from quarantined files */
  fileRiskLevels?: FileRiskLevel[];
  /** Sandbox scores (0-100, higher = more malicious) */
  sandboxScores?: number[];
  /** Phishing verdict if email analysis ran */
  phishingVerdict?: PhishingVerdict | null;
  /** Threat feed match count */
  threatFeedMatches?: number;
}

/**
 * Computes aggregate threat level from session data.
 *
 * Priority: any malicious signal → malicious.
 * Suspicious signals accumulate — 3+ suspicious → malicious.
 */
function computeThreatLevel(signals: ThreatSignals): ThreatLevel {
  let maliciousCount = 0;
  let suspiciousCount = 0;

  // IOC verdicts
  for (const v of signals.iocVerdicts || []) {
    if (v === 'malicious') maliciousCount++;
    if (v === 'suspicious') suspiciousCount++;
  }

  // File risk levels
  for (const r of signals.fileRiskLevels || []) {
    if (r === 'critical' || r === 'high') maliciousCount++;
    if (r === 'medium') suspiciousCount++;
  }

  // Sandbox scores
  for (const s of signals.sandboxScores || []) {
    if (s >= 70) maliciousCount++;
    else if (s >= 40) suspiciousCount++;
  }

  // Phishing verdict
  if (signals.phishingVerdict === 'likely_phishing') maliciousCount++;
  else if (signals.phishingVerdict === 'suspicious') suspiciousCount++;

  // Threat feed matches — direct indicator
  if ((signals.threatFeedMatches || 0) >= 3) maliciousCount++;
  else if ((signals.threatFeedMatches || 0) >= 1) suspiciousCount++;

  // Decision
  if (maliciousCount > 0) return 'malicious';
  if (suspiciousCount >= 3) return 'malicious';
  if (suspiciousCount > 0) return 'suspicious';
  return 'clean';
}

interface ThreatLevelProviderProps {
  children: React.ReactNode;
  signals: ThreatSignals;
}

export function ThreatLevelProvider({ children, signals }: ThreatLevelProviderProps) {
  const threatLevel = useMemo(() => computeThreatLevel(signals), [signals]);

  // Set the data-threat attribute on <html> so CSS responds
  useEffect(() => {
    document.documentElement.dataset.threat = threatLevel;
    return () => {
      document.documentElement.dataset.threat = 'clean';
    };
  }, [threatLevel]);

  const value = useMemo(() => ({ threatLevel }), [threatLevel]);

  return (
    <ThreatLevelContext.Provider value={value}>
      {children}
    </ThreatLevelContext.Provider>
  );
}
