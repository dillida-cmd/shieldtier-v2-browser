import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { useStore } from './store';
import { ipcCall } from './ipc/bridge';
import './globals.css';

declare global {
  interface Window {
    __shieldtier_push?: (event: string, data: unknown) => void;
  }
}

ipcCall<{ theme?: string; fontSize?: string }>('get_config', { key: 'ui' }).then((prefs) => {
  if (prefs?.theme) {
    document.documentElement.setAttribute('data-theme', prefs.theme);
    useStore.getState().setTheme(prefs.theme as 'dark' | 'light');
  }
  if (prefs?.fontSize) {
    document.documentElement.setAttribute('data-font', prefs.fontSize);
    useStore.getState().setFontSize(prefs.fontSize as 'sm' | 'md' | 'lg');
  }
}).catch(() => {});

window.__shieldtier_push = (event: string, data: unknown) => {
  const store = useStore.getState();
  const d = data as Record<string, unknown>;

  switch (event) {
    case 'analysis_complete':
      store.setAnalysis(
        d.sha256 as string,
        d.result as Parameters<typeof store.setAnalysis>[1],
      );
      break;
    case 'download_detected':
      store.setCurrentSha256(d.sha256 as string);
      store.setCurrentDownload({
        sha256: d.sha256 as string,
        filename: d.filename as string,
        size: d.size as number,
      });
      break;
    case 'vm_event':
      store.addVmEvent(d as unknown as Parameters<typeof store.addVmEvent>[0]);
      break;
    case 'vm_status':
      store.setVmStatus((d as { status: string }).status as Parameters<typeof store.setVmStatus>[0]);
      break;
    case 'vm_findings':
      store.setVmFindings(d as unknown as Parameters<typeof store.setVmFindings>[0]);
      break;
    case 'vm_process_tree':
      store.setVmProcessTree(d as unknown as Parameters<typeof store.setVmProcessTree>[0]);
      break;
    case 'vm_network_summary':
      store.setVmNetworkSummary(d as unknown as Parameters<typeof store.setVmNetworkSummary>[0]);
      break;
    case 'capture_update':
      store.setCaptureData(d as unknown as Parameters<typeof store.setCaptureData>[0]);
      break;
    case 'navigation_state':
      store.setNavState(d as unknown as Parameters<typeof store.setNavState>[0]);
      break;
    case 'screenshot':
      store.addScreenshot(d.url as string);
      break;
    case 'captured_file':
      store.addCapturedFile(d as unknown as Parameters<typeof store.addCapturedFile>[0]);
      break;
    case 'vm_stats':
      store.setVmStats(d.cpu as number, d.ram as number, d.net as number);
      break;
    case 'chat_message':
      store.addChatMessage(d.contact_id as string, d.message as any);
      break;
    case 'chat_presence':
      store.setChatPresence(d.contact_id as string, d.presence as any);
      break;
    case 'chat_status':
      store.setChatConnectionStatus(d.status as any);
      break;
  }
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
