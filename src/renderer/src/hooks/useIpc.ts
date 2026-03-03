import { useState, useCallback } from 'react';
import { ipcCall } from '../ipc/bridge';

interface UseIpcResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  execute: (action: string, payload?: Record<string, unknown>) => Promise<T | null>;
}

export function useIpc<T = unknown>(): UseIpcResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const execute = useCallback(async (action: string, payload?: Record<string, unknown>) => {
    setLoading(true);
    setError(null);
    try {
      const result = await ipcCall<T>(action, payload);
      setData(result);
      return result;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Unknown error';
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { data, loading, error, execute };
}
