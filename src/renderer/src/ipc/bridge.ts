import type { IpcResponse } from './types';

declare global {
  interface Window {
    cefQuery?: (params: {
      request: string;
      onSuccess: (response: string) => void;
      onFailure: (code: number, message: string) => void;
    }) => void;
  }
}

export function ipcCall<T = unknown>(
  action: string,
  payload: Record<string, unknown> = {},
): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!window.cefQuery) {
      console.warn(`[IPC stub] ${action}`, payload);
      setTimeout(() => resolve({} as T), 50);
      return;
    }

    window.cefQuery({
      request: JSON.stringify({ action, payload }),
      onSuccess: (response: string) => {
        try {
          const parsed: IpcResponse<T> = JSON.parse(response);
          if (parsed.success) {
            resolve(parsed.data);
          } else {
            reject(new Error(parsed.error ?? 'unknown_error'));
          }
        } catch {
          reject(new Error('Failed to parse IPC response'));
        }
      },
      onFailure: (_code: number, message: string) => {
        reject(new Error(message));
      },
    });
  });
}
