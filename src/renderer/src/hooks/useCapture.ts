import { useEffect, useRef } from 'react';
import { ipcCall } from '../ipc/bridge';
import { useStore } from '../store';
import type { CaptureData } from '../ipc/types';

export function useCapturePolling(intervalMs = 1000) {
  const { capturing, setCaptureData } = useStore();
  const timerRef = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => {
    if (!capturing) return;

    const poll = async () => {
      try {
        const data = await ipcCall<CaptureData>('get_capture', { browser_id: 0 });
        setCaptureData(data);
      } catch {
        // Silently retry
      }
    };

    poll();
    timerRef.current = setInterval(poll, intervalMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [capturing, intervalMs, setCaptureData]);
}
