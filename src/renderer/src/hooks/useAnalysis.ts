import { useEffect, useRef } from 'react';
import { ipcCall } from '../ipc/bridge';
import { useStore } from '../store';
import type { AnalysisResult } from '../ipc/types';

export function useAnalysisPolling(intervalMs = 2000) {
  const { currentSha256, analysisStatus, setAnalysis } = useStore();
  const timerRef = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => {
    if (!currentSha256 || analysisStatus === 'complete' || analysisStatus === 'error') {
      return;
    }

    const poll = async () => {
      try {
        const result = await ipcCall<AnalysisResult>('get_analysis_result', { sha256: currentSha256 });
        if (result) {
          setAnalysis(currentSha256, result);
        }
      } catch {
        // Silently retry on next interval
      }
    };

    poll();
    timerRef.current = setInterval(poll, intervalMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [currentSha256, analysisStatus, intervalMs, setAnalysis]);
}
