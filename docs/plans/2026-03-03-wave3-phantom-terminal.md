# Wave 3 — Phantom Terminal UI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the React renderer UI with a multi-zone ANY.RUN-style workspace, Phantom Terminal dark theme, and CefMessageRouter IPC bridge.

**Architecture:** Single-page React app loaded by CEF via `file://`. Multi-zone layout: icon rail (52px) + top row (browser zone | VM zone) + horizontal splitter + bottom row (data zone with 10 tabbed panels). All native communication through `window.cefQuery()` JSON bridge mapping to the 12 existing IPC actions. Zustand for global state. Tailwind CSS 4 with CSS custom properties for the Phantom Terminal theme.

**Tech Stack:** React 19, TypeScript 5.7, Tailwind CSS 4 (Vite plugin), Radix UI (headless), Zustand, Vite 6, JetBrains Mono

**Design doc:** `docs/plans/2026-03-03-wave3-ui-design.md`

---

## Task 1: Project Scaffold

**Files:**
- Create: `src/renderer/package.json`
- Create: `src/renderer/vite.config.ts`
- Create: `src/renderer/tsconfig.json`
- Create: `src/renderer/index.html`
- Create: `src/renderer/src/main.tsx`
- Create: `src/renderer/src/App.tsx`

**Step 1: Create package.json**

```json
{
  "name": "shieldtier-renderer",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "@radix-ui/react-scroll-area": "^1.2.3",
    "@radix-ui/react-tooltip": "^1.1.8",
    "@radix-ui/react-dropdown-menu": "^2.1.6",
    "@radix-ui/react-tabs": "^1.1.3",
    "@radix-ui/react-separator": "^1.1.1",
    "@radix-ui/react-slot": "^1.1.1",
    "zustand": "^5.0.3",
    "clsx": "^2.1.1",
    "tailwind-merge": "^3.0.2",
    "class-variance-authority": "^0.7.1"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@tailwindcss/vite": "^4.1.0",
    "@vitejs/plugin-react": "^4.3.4",
    "tailwindcss": "^4.1.0",
    "typescript": "^5.7.0",
    "vite": "^6.2.0"
  }
}
```

**Step 2: Create vite.config.ts**

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  root: path.resolve(__dirname),
  base: './',
  build: {
    outDir: path.resolve(__dirname, 'dist'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

**Step 4: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ShieldTier</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
```

**Step 5: Create main.tsx**

```tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './globals.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

**Step 6: Create App.tsx (stub)**

```tsx
export function App() {
  return (
    <div className="h-screen w-screen bg-[var(--st-bg-primary)] text-[var(--st-text-primary)] font-mono text-sm">
      <p className="p-4">ShieldTier — Phantom Terminal</p>
    </div>
  );
}
```

**Step 7: Install dependencies and verify build**

Run: `cd src/renderer && npm install && npx vite build`
Expected: Clean build producing dist/index.html + assets

**Step 8: Commit**

```bash
git add src/renderer/package.json src/renderer/vite.config.ts src/renderer/tsconfig.json src/renderer/index.html src/renderer/src/main.tsx src/renderer/src/App.tsx
git commit -m "feat(wave3): scaffold renderer project — React 19 + Tailwind 4 + Vite 6"
```

---

## Task 2: Phantom Terminal Theme + Utilities

**Files:**
- Create: `src/renderer/src/globals.css`
- Create: `src/renderer/src/lib/utils.ts`
- Create: `src/renderer/src/components/common/Badge.tsx`
- Create: `src/renderer/src/components/common/StatusDot.tsx`
- Create: `src/renderer/src/components/common/Panel.tsx`

**Step 1: Create globals.css**

```css
@import "tailwindcss";

@font-face {
  font-family: 'JetBrains Mono';
  font-weight: 100 800;
  font-display: swap;
  src: url('/fonts/JetBrainsMono-Variable.woff2') format('woff2');
}

:root {
  --st-bg-primary: #0a0a0a;
  --st-bg-panel: #0f1117;
  --st-bg-elevated: #151921;
  --st-bg-hover: #1a1f2e;
  --st-border: #1c2030;
  --st-border-bright: #2a3045;
  --st-text-primary: #00ff41;
  --st-text-secondary: #00cc33;
  --st-text-muted: #2d5a35;
  --st-text-label: #94a3b8;
  --st-accent: #3b82f6;
  --st-accent-dim: rgba(59, 130, 246, 0.1);
  --st-severity-critical: #ff0040;
  --st-severity-high: #ff6600;
  --st-severity-medium: #ffcc00;
  --st-severity-low: #00ccff;
  --st-severity-clean: #00ff41;
  --st-font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace;
  --st-font-ui: 'Inter', system-ui, -apple-system, sans-serif;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html, body, #root {
  height: 100%;
  width: 100%;
  overflow: hidden;
  background: var(--st-bg-primary);
  color: var(--st-text-primary);
  font-family: var(--st-font-mono);
  font-size: 12px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* Scanline overlay — applied to #root */
#root::after {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 9999;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 3px
  );
}

/* Glass morphism utility */
.glass {
  background: rgba(15, 17, 23, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}

.glass-heavy {
  background: rgba(10, 10, 10, 0.92);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

/* Glow effect */
.glow {
  text-shadow: 0 0 6px var(--st-text-primary);
}

.glow-accent {
  text-shadow: 0 0 6px var(--st-accent);
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: var(--st-border-bright);
  border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
  background: var(--st-text-muted);
}

/* Selection */
::selection {
  background: rgba(59, 130, 246, 0.3);
  color: var(--st-text-primary);
}
```

**Step 2: Create lib/utils.ts**

```typescript
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

**Step 3: Create common/Badge.tsx**

```tsx
import { cn } from '../../lib/utils';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'clean';

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)]',
  high: 'bg-[var(--st-severity-high)]/15 text-[var(--st-severity-high)]',
  medium: 'bg-[var(--st-severity-medium)]/15 text-[var(--st-severity-medium)]',
  low: 'bg-[var(--st-severity-low)]/15 text-[var(--st-severity-low)]',
  info: 'bg-[var(--st-accent)]/15 text-[var(--st-accent)]',
  clean: 'bg-[var(--st-severity-clean)]/15 text-[var(--st-severity-clean)]',
};

interface BadgeProps {
  severity: Severity;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ severity, children, className }: BadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono',
      SEVERITY_STYLES[severity],
      className,
    )}>
      {children}
    </span>
  );
}

interface CountBadgeProps {
  count: number;
  color?: 'blue' | 'red' | 'purple' | 'green';
  className?: string;
}

const COUNT_COLORS = {
  blue: 'bg-blue-500/15 text-blue-400',
  red: 'bg-red-500/15 text-red-400',
  purple: 'bg-purple-500/15 text-purple-400',
  green: 'bg-green-500/15 text-green-400',
};

export function CountBadge({ count, color = 'blue', className }: CountBadgeProps) {
  if (count <= 0) return null;
  return (
    <span className={cn(
      'text-[9px] font-bold font-mono px-1 rounded',
      COUNT_COLORS[color],
      className,
    )}>
      {count > 99 ? '99+' : count}
    </span>
  );
}
```

**Step 4: Create common/StatusDot.tsx**

```tsx
import { cn } from '../../lib/utils';

interface StatusDotProps {
  status: 'idle' | 'active' | 'error' | 'recording';
  className?: string;
}

const STATUS_STYLES = {
  idle: 'bg-[var(--st-text-muted)]',
  active: 'bg-[var(--st-severity-clean)]',
  error: 'bg-[var(--st-severity-critical)]',
  recording: 'bg-[var(--st-severity-critical)]',
};

export function StatusDot({ status, className }: StatusDotProps) {
  return (
    <span className={cn('relative inline-flex h-2 w-2', className)}>
      {(status === 'active' || status === 'recording') && (
        <span className={cn(
          'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
          STATUS_STYLES[status],
        )} />
      )}
      <span className={cn('relative inline-flex rounded-full h-2 w-2', STATUS_STYLES[status])} />
    </span>
  );
}
```

**Step 5: Create common/Panel.tsx**

```tsx
import { cn } from '../../lib/utils';

interface PanelProps {
  title?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPad?: boolean;
}

export function Panel({ title, actions, children, className, noPad }: PanelProps) {
  return (
    <div className={cn('flex flex-col h-full bg-[var(--st-bg-panel)] border border-[var(--st-border)] rounded-sm overflow-hidden', className)}>
      {title && (
        <div className="flex items-center justify-between h-7 px-2 border-b border-[var(--st-border)] flex-shrink-0">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">{title}</span>
          {actions && <div className="flex items-center gap-1">{actions}</div>}
        </div>
      )}
      <div className={cn('flex-1 overflow-auto', !noPad && 'p-2')}>
        {children}
      </div>
    </div>
  );
}
```

**Step 6: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 7: Commit**

```bash
git add src/renderer/src/globals.css src/renderer/src/lib/utils.ts src/renderer/src/components/common/
git commit -m "feat(wave3): add Phantom Terminal theme, utilities, and common components"
```

---

## Task 3: IPC Bridge + Types + Zustand Store

**Files:**
- Create: `src/renderer/src/ipc/bridge.ts`
- Create: `src/renderer/src/ipc/types.ts`
- Create: `src/renderer/src/store/index.ts`

**Step 1: Create ipc/types.ts**

These types mirror the C++ `ipc_protocol.h` actions and the native response shapes.

```typescript
// IPC actions matching src/native/ipc/ipc_protocol.h
export type IpcAction =
  | 'navigate'
  | 'get_tabs'
  | 'close_tab'
  | 'analyze_download'
  | 'get_analysis_result'
  | 'get_config'
  | 'set_config'
  | 'export_report'
  | 'get_threat_feeds'
  | 'start_capture'
  | 'stop_capture'
  | 'get_capture';

// Response wrapper from C++ ipc::make_success / ipc::make_error
export interface IpcResponse<T = unknown> {
  success: boolean;
  data: T;
  error?: string;
}

// --- Domain types matching native structs ---

export interface TabInfo {
  tab_id: string;
  browser_id: number;
  in_memory: boolean;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  title: string;
  description: string;
  severity: SeverityLevel;
  engine: string;
  metadata: Record<string, unknown>;
}

export interface ThreatVerdict {
  score: number;
  severity: SeverityLevel;
  label: string;
  findings: Finding[];
  engine_summaries: Record<string, unknown>;
}

export interface AnalysisResult {
  status: 'pending' | 'complete' | 'error' | 'not_found';
  verdict?: ThreatVerdict;
  error?: string;
}

export interface CaptureData {
  capturing: boolean;
  request_count: number;
  har: string;
}

export interface HarEntry {
  method: string;
  url: string;
  status: number;
  size: number;
  time: number;
  mimeType: string;
}

export interface HarLog {
  log: {
    entries: Array<{
      request: { method: string; url: string };
      response: { status: number; content: { size: number; mimeType: string } };
      time: number;
    }>;
  };
}

// VM types
export type VmStatus = 'idle' | 'booting' | 'running' | 'complete' | 'error';

export interface VmEvent {
  timestamp: string;
  category: string;
  action: string;
  detail: string;
  severity?: SeverityLevel;
}

export interface ProcessNode {
  pid: number;
  name: string;
  children: ProcessNode[];
}

export interface NetworkSummary {
  dns_query_count: number;
  http_request_count: number;
  connection_count: number;
}
```

**Step 2: Create ipc/bridge.ts**

```typescript
import type { IpcResponse } from './types';

// CEF injects window.cefQuery when running inside the browser shell.
// During development (vite dev), we stub it so the UI can render without CEF.
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
      // Dev mode stub — resolve with empty data after a short delay
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
        } catch (e) {
          reject(new Error('Failed to parse IPC response'));
        }
      },
      onFailure: (_code: number, message: string) => {
        reject(new Error(message));
      },
    });
  });
}
```

**Step 3: Create store/index.ts**

```typescript
import { create } from 'zustand';
import type {
  AnalysisResult,
  CaptureData,
  VmStatus,
  VmEvent,
  Finding,
  ProcessNode,
  NetworkSummary,
} from '../ipc/types';

export type LayoutPreset = 'brw' | 'eml' | 'mal' | 'log';
export type TopLeftTab = 'browser' | 'email' | 'logs';

export type BottomTab =
  | 'network' | 'ioc' | 'screenshots' | 'files'
  | 'sandbox' | 'findings' | 'mitre'
  | 'activity' | 'timeline' | 'process';

interface PresetConfig {
  topLeft: TopLeftTab;
  vmCollapsed: boolean;
  bottomTabs: [BottomTab, BottomTab, BottomTab];
}

const PRESET_CONFIGS: Record<LayoutPreset, PresetConfig> = {
  brw: { topLeft: 'browser', vmCollapsed: false, bottomTabs: ['network', 'ioc', 'activity'] },
  eml: { topLeft: 'email', vmCollapsed: true, bottomTabs: ['findings', 'ioc', 'mitre'] },
  mal: { topLeft: 'browser', vmCollapsed: false, bottomTabs: ['sandbox', 'files', 'mitre'] },
  log: { topLeft: 'logs', vmCollapsed: true, bottomTabs: ['timeline', 'activity', 'process'] },
};

interface ShieldTierState {
  // Layout
  preset: LayoutPreset;
  topSplit: number;
  mainSplit: number;
  vmCollapsed: boolean;
  activeTopLeft: TopLeftTab;
  bottomTabs: [BottomTab, BottomTab, BottomTab];
  bottomPrimaryTab: BottomTab;

  // Session
  caseId: string;
  caseName: string;

  // Analysis
  currentSha256: string | null;
  analysisStatus: 'idle' | 'pending' | 'complete' | 'error';
  analysisResult: AnalysisResult | null;

  // Network capture
  capturing: boolean;
  captureData: CaptureData | null;

  // VM Sandbox
  vmStatus: VmStatus;
  vmEvents: VmEvent[];
  vmFindings: Finding[];
  vmProcessTree: ProcessNode[];
  vmNetworkSummary: NetworkSummary | null;

  // Actions
  setPreset: (preset: LayoutPreset) => void;
  setTopSplit: (ratio: number) => void;
  setMainSplit: (ratio: number) => void;
  setActiveTopLeft: (tab: TopLeftTab) => void;
  setBottomPrimaryTab: (tab: BottomTab) => void;
  setBottomTabs: (tabs: [BottomTab, BottomTab, BottomTab]) => void;
  setAnalysis: (sha256: string, result: AnalysisResult) => void;
  setCaptureData: (data: CaptureData | null) => void;
  setCapturing: (capturing: boolean) => void;
  setVmStatus: (status: VmStatus) => void;
  addVmEvent: (event: VmEvent) => void;
  setVmFindings: (findings: Finding[]) => void;
  setVmProcessTree: (tree: ProcessNode[]) => void;
  setVmNetworkSummary: (summary: NetworkSummary | null) => void;
}

export const useStore = create<ShieldTierState>()((set) => ({
  // Layout defaults (BRW preset)
  preset: 'brw',
  topSplit: 0.55,
  mainSplit: 0.57,
  vmCollapsed: false,
  activeTopLeft: 'browser',
  bottomTabs: ['network', 'ioc', 'activity'],
  bottomPrimaryTab: 'network',

  // Session
  caseId: '',
  caseName: '',

  // Analysis
  currentSha256: null,
  analysisStatus: 'idle',
  analysisResult: null,

  // Network capture
  capturing: false,
  captureData: null,

  // VM Sandbox
  vmStatus: 'idle',
  vmEvents: [],
  vmFindings: [],
  vmProcessTree: [],
  vmNetworkSummary: null,

  // Actions
  setPreset: (preset) => {
    const config = PRESET_CONFIGS[preset];
    set({
      preset,
      activeTopLeft: config.topLeft,
      vmCollapsed: config.vmCollapsed,
      bottomTabs: config.bottomTabs,
      bottomPrimaryTab: config.bottomTabs[0],
    });
  },
  setTopSplit: (topSplit) => set({ topSplit: Math.max(0.2, Math.min(0.8, topSplit)) }),
  setMainSplit: (mainSplit) => set({ mainSplit: Math.max(0.25, Math.min(0.8, mainSplit)) }),
  setActiveTopLeft: (activeTopLeft) => set({ activeTopLeft }),
  setBottomPrimaryTab: (bottomPrimaryTab) => set({ bottomPrimaryTab }),
  setBottomTabs: (bottomTabs) => set({ bottomTabs }),
  setAnalysis: (sha256, result) => set({
    currentSha256: sha256,
    analysisStatus: result.status === 'complete' ? 'complete' : result.status === 'error' ? 'error' : 'pending',
    analysisResult: result,
  }),
  setCaptureData: (captureData) => set({ captureData }),
  setCapturing: (capturing) => set({ capturing }),
  setVmStatus: (vmStatus) => set({ vmStatus }),
  addVmEvent: (event) => set((s) => ({ vmEvents: [...s.vmEvents, event] })),
  setVmFindings: (vmFindings) => set({ vmFindings }),
  setVmProcessTree: (vmProcessTree) => set({ vmProcessTree }),
  setVmNetworkSummary: (vmNetworkSummary) => set({ vmNetworkSummary }),
}));
```

**Step 4: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 5: Commit**

```bash
git add src/renderer/src/ipc/ src/renderer/src/store/
git commit -m "feat(wave3): add IPC bridge, types, and Zustand store"
```

---

## Task 4: Splitter Components

**Files:**
- Create: `src/renderer/src/components/workspace/SplitterH.tsx`
- Create: `src/renderer/src/components/workspace/SplitterV.tsx`

**Step 1: Create SplitterH.tsx**

```tsx
import { useCallback, useRef } from 'react';

interface SplitterHProps {
  onDrag: (deltaY: number) => void;
  onDragEnd?: () => void;
}

export function SplitterH({ onDrag, onDragEnd }: SplitterHProps) {
  const dragging = useRef(false);
  const lastY = useRef(0);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastY.current = e.clientY;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientY - lastY.current);
    lastY.current = e.clientY;
  }, [onDrag]);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    dragging.current = false;
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className="h-[5px] flex-shrink-0 cursor-ns-resize flex items-center justify-center border-t border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/20 transition-colors"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="w-10 h-[2px] rounded bg-[var(--st-text-muted)] opacity-30" />
    </div>
  );
}
```

**Step 2: Create SplitterV.tsx**

```tsx
import { useCallback, useRef } from 'react';

interface SplitterVProps {
  onDrag: (deltaX: number) => void;
  onDragEnd?: () => void;
}

export function SplitterV({ onDrag, onDragEnd }: SplitterVProps) {
  const dragging = useRef(false);
  const lastX = useRef(0);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
    lastX.current = e.clientX;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragging.current) return;
    onDrag(e.clientX - lastX.current);
    lastX.current = e.clientX;
  }, [onDrag]);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    dragging.current = false;
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className="w-[5px] flex-shrink-0 cursor-ew-resize flex items-center justify-center border-l border-r border-[var(--st-border)] bg-[var(--st-bg-panel)] hover:bg-[var(--st-accent)]/20 transition-colors"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <div className="h-8 w-[2px] rounded bg-[var(--st-text-muted)] opacity-20" />
    </div>
  );
}
```

**Step 3: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 4: Commit**

```bash
git add src/renderer/src/components/workspace/SplitterH.tsx src/renderer/src/components/workspace/SplitterV.tsx
git commit -m "feat(wave3): add horizontal and vertical splitter components"
```

---

## Task 5: TopBar Component

**Files:**
- Create: `src/renderer/src/components/workspace/TopBar.tsx`

Matches the mockup: SHIELDTIER logo | Case ID + Name | REC timer | SOCKS proxy indicator | Status badge

**Step 1: Create TopBar.tsx**

```tsx
import { StatusDot } from '../common/StatusDot';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';

export function TopBar() {
  const { caseId, caseName, capturing, analysisResult } = useStore();

  const verdictSeverity = analysisResult?.verdict?.severity ?? null;
  const verdictLabel = analysisResult?.verdict?.label ?? 'CLEAN';

  return (
    <div className="glass-heavy h-10 flex items-center border-b border-[var(--st-border)] px-3 gap-4 flex-shrink-0 z-10">
      {/* Logo */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="w-5 h-5 rounded bg-[var(--st-accent)] flex items-center justify-center">
          <span className="text-white text-[10px] font-black">S</span>
        </div>
        <span className="text-[var(--st-text-label)] text-[11px] font-bold tracking-widest uppercase">
          ShieldTier
        </span>
      </div>

      {/* Separator */}
      <div className="w-px h-5 bg-[var(--st-border)]" />

      {/* Case info */}
      <div className="flex items-center gap-2 min-w-0">
        {caseId && (
          <span className="text-[var(--st-accent)] text-[11px] font-mono font-bold flex-shrink-0">
            {caseId}
          </span>
        )}
        {caseName && (
          <span className="text-[var(--st-text-label)] text-[11px] truncate">
            {caseName}
          </span>
        )}
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* REC indicator */}
      {capturing && (
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <StatusDot status="recording" />
          <span className="text-[var(--st-severity-critical)] text-[10px] font-bold tracking-wider">
            REC
          </span>
        </div>
      )}

      {/* Status badge */}
      <Badge severity={verdictSeverity ?? 'clean'} className="flex-shrink-0">
        {verdictLabel}
      </Badge>
    </div>
  );
}
```

**Step 2: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 3: Commit**

```bash
git add src/renderer/src/components/workspace/TopBar.tsx
git commit -m "feat(wave3): add TopBar with case info, REC indicator, and verdict badge"
```

---

## Task 6: IconRail Component

**Files:**
- Create: `src/renderer/src/components/workspace/IconRail.tsx`

52px icon rail with layout presets (BRW/EML/MAL/LOG), YARA/feeds badges, REC indicator.

**Step 1: Create IconRail.tsx**

```tsx
import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { useStore, type LayoutPreset } from '../../store';

const PRESETS: Array<{ id: LayoutPreset; label: string }> = [
  { id: 'brw', label: 'BRW' },
  { id: 'eml', label: 'EML' },
  { id: 'mal', label: 'MAL' },
  { id: 'log', label: 'LOG' },
];

export function IconRail() {
  const { preset, setPreset, capturing } = useStore();

  return (
    <div className="glass-heavy w-[52px] border-r border-[var(--st-border)] flex flex-col items-center py-2 flex-shrink-0 gap-1">
      {/* Layout presets */}
      {PRESETS.map((p) => (
        <button
          key={p.id}
          onClick={() => setPreset(p.id)}
          className={cn(
            'w-10 h-9 rounded-lg border-none flex flex-col items-center justify-center cursor-pointer transition-colors text-[9px] font-bold tracking-wider',
            preset === p.id
              ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)] glow-accent'
              : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)]',
          )}
        >
          {p.label}
        </button>
      ))}

      {/* Separator */}
      <div className="w-7 h-px bg-[var(--st-border)] my-1" />

      {/* YARA */}
      <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2L2 7l10 5 10-5-10-5z" />
          <path d="M2 17l10 5 10-5" />
          <path d="M2 12l10 5 10-5" />
        </svg>
        <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">YARA</span>
        <div className="absolute -top-0.5 -right-0.5">
          <CountBadge count={24} color="purple" />
        </div>
      </button>

      {/* Feeds */}
      <button className="w-10 h-9 rounded-lg border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] flex flex-col items-center justify-center cursor-pointer transition-colors relative">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 2a10 10 0 0 1 0 20" />
          <path d="M2 12h20" />
        </svg>
        <span className="text-[7px] font-medium uppercase tracking-wide opacity-70">FEED</span>
      </button>

      {/* Spacer */}
      <div className="flex-1" />

      {/* REC indicator */}
      <div className="flex flex-col items-center gap-0.5 mb-1">
        <StatusDot status={capturing ? 'recording' : 'idle'} />
        <span className={cn(
          'text-[7px] font-bold uppercase tracking-wider',
          capturing ? 'text-[var(--st-severity-critical)]' : 'text-[var(--st-text-muted)]',
        )}>
          REC
        </span>
      </div>
    </div>
  );
}
```

**Step 2: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 3: Commit**

```bash
git add src/renderer/src/components/workspace/IconRail.tsx
git commit -m "feat(wave3): add IconRail with layout presets, YARA/feed badges, REC indicator"
```

---

## Task 7: BrowserZone Component

**Files:**
- Create: `src/renderer/src/components/workspace/BrowserZone.tsx`

URL bar with SANDBOXED badge, back/forward/refresh controls, embedded view placeholder.

**Step 1: Create BrowserZone.tsx**

```tsx
import { useState, useCallback } from 'react';
import { Badge } from '../common/Badge';
import { ipcCall } from '../../ipc/bridge';

export function BrowserZone() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useCallback(async () => {
    const trimmed = url.trim();
    if (!trimmed) return;

    let target = trimmed;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }

    setLoading(true);
    try {
      await ipcCall('navigate', { url: target });
    } catch (e) {
      console.error('Navigation failed:', e);
    } finally {
      setLoading(false);
    }
  }, [url]);

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') navigate();
  }, [navigate]);

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-primary)]">
      {/* URL bar */}
      <div className="flex items-center h-10 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0 bg-[var(--st-bg-panel)]">
        {/* Nav buttons */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <NavButton label="Back">
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </NavButton>
          <NavButton label="Forward">
            <path d="M5 12h14M12 5l7 7-7 7" />
          </NavButton>
          <NavButton label="Refresh">
            <path d="M23 4v6h-6M1 20v-6h6" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </NavButton>
        </div>

        {/* SANDBOXED badge */}
        <Badge severity="info" className="flex-shrink-0">SANDBOXED</Badge>

        {/* URL input */}
        <div className="flex-1 flex items-center bg-[var(--st-bg-primary)] rounded border border-[var(--st-border)] px-2 h-7">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--st-text-muted)" strokeWidth="2" className="flex-shrink-0 mr-1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Enter URL to investigate..."
            className="flex-1 bg-transparent border-none outline-none text-[var(--st-text-primary)] font-mono text-[11px] placeholder:text-[var(--st-text-muted)]"
          />
          {loading && (
            <div className="w-3 h-3 border-2 border-[var(--st-accent)] border-t-transparent rounded-full animate-spin flex-shrink-0" />
          )}
        </div>
      </div>

      {/* Browser viewport placeholder */}
      <div className="flex-1 flex items-center justify-center bg-[var(--st-bg-primary)]">
        <div className="flex flex-col items-center gap-3 text-[var(--st-text-muted)]">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.3">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
          <span className="text-[11px]">Navigate to a URL to begin analysis</span>
        </div>
      </div>
    </div>
  );
}

function NavButton({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <button
      title={label}
      className="w-7 h-7 rounded border-none bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-secondary)] hover:bg-[var(--st-bg-hover)] cursor-pointer transition-colors flex items-center justify-center"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {children}
      </svg>
    </button>
  );
}
```

**Step 2: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 3: Commit**

```bash
git add src/renderer/src/components/workspace/BrowserZone.tsx
git commit -m "feat(wave3): add BrowserZone with URL bar, SANDBOXED badge, and navigation"
```

---

## Task 8: VMZone Component

**Files:**
- Create: `src/renderer/src/components/vm/VMControls.tsx`
- Create: `src/renderer/src/components/vm/VMTerminal.tsx`
- Create: `src/renderer/src/components/vm/VMStats.tsx`
- Create: `src/renderer/src/components/workspace/VMZone.tsx`

**Step 1: Create VMControls.tsx**

```tsx
import { useState } from 'react';
import { cn } from '../../lib/utils';
import { Badge } from '../common/Badge';
import { StatusDot } from '../common/StatusDot';
import { useStore } from '../../store';

const OS_OPTIONS = ['Alpine 3.19', 'ReactOS 0.4', 'Windows 10 x64'];

export function VMControls() {
  const { vmStatus } = useStore();
  const [selectedOs, setSelectedOs] = useState(OS_OPTIONS[0]);

  const statusLabel = vmStatus === 'running' ? 'RUNNING' : vmStatus === 'booting' ? 'BOOTING' : vmStatus === 'complete' ? 'COMPLETE' : 'IDLE';
  const statusSeverity = vmStatus === 'running' ? 'clean' : vmStatus === 'booting' ? 'medium' : vmStatus === 'complete' ? 'info' : 'low';
  const dotStatus = vmStatus === 'running' ? 'active' as const : vmStatus === 'error' ? 'error' as const : 'idle' as const;

  return (
    <div className="flex items-center h-8 px-2 gap-2 border-b border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      {/* OS selector */}
      <select
        value={selectedOs}
        onChange={(e) => setSelectedOs(e.target.value)}
        className="bg-[var(--st-bg-primary)] border border-[var(--st-border)] rounded text-[var(--st-text-label)] text-[10px] font-mono px-1.5 py-0.5 outline-none cursor-pointer"
      >
        {OS_OPTIONS.map((os) => (
          <option key={os} value={os}>{os}</option>
        ))}
      </select>

      {/* Status badge */}
      <div className="flex items-center gap-1.5">
        <StatusDot status={dotStatus} />
        <Badge severity={statusSeverity}>{statusLabel}</Badge>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-1">
        <button className={cn(
          'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
          vmStatus === 'idle'
            ? 'bg-[var(--st-severity-clean)]/15 text-[var(--st-severity-clean)] hover:bg-[var(--st-severity-clean)]/25'
            : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
        )}>
          START
        </button>
        <button className={cn(
          'px-2 py-0.5 rounded text-[10px] font-bold border-none cursor-pointer transition-colors',
          vmStatus === 'running'
            ? 'bg-[var(--st-severity-critical)]/15 text-[var(--st-severity-critical)] hover:bg-[var(--st-severity-critical)]/25'
            : 'bg-[var(--st-bg-hover)] text-[var(--st-text-muted)] cursor-not-allowed',
        )}>
          STOP
        </button>
      </div>

      <div className="flex-1" />

      {/* LIVE indicator */}
      {vmStatus === 'running' && (
        <Badge severity="critical" className="animate-pulse">LIVE - ANALYZING</Badge>
      )}
    </div>
  );
}
```

**Step 2: Create VMTerminal.tsx**

```tsx
import { useRef, useEffect } from 'react';
import { useStore } from '../../store';
import { cn } from '../../lib/utils';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-[var(--st-severity-critical)]',
  high: 'text-[var(--st-severity-high)]',
  medium: 'text-[var(--st-severity-medium)]',
  low: 'text-[var(--st-severity-low)]',
};

export function VMTerminal() {
  const { vmEvents } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [vmEvents.length]);

  return (
    <div ref={scrollRef} className="flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed bg-[var(--st-bg-primary)]">
      {vmEvents.length === 0 ? (
        <div className="text-[var(--st-text-muted)] text-[10px]">
          <span className="text-[var(--st-severity-clean)]">root@sandbox:~#</span> Waiting for VM events...
        </div>
      ) : (
        vmEvents.map((event, i) => (
          <div key={i} className="flex gap-2 hover:bg-[var(--st-bg-hover)] px-1 rounded">
            <span className="text-[var(--st-text-muted)] flex-shrink-0 text-[10px]">
              {event.timestamp}
            </span>
            <span className="text-[var(--st-severity-clean)] flex-shrink-0">
              [agent]
            </span>
            <span className={cn(
              event.severity ? SEVERITY_COLORS[event.severity] : 'text-[var(--st-text-primary)]',
            )}>
              {event.detail}
            </span>
          </div>
        ))
      )}
    </div>
  );
}
```

**Step 3: Create VMStats.tsx**

```tsx
import { cn } from '../../lib/utils';

interface StatBarProps {
  label: string;
  value: number;
  max: number;
  unit: string;
  color: string;
}

function StatBar({ label, value, max, unit, color }: StatBarProps) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-1.5 text-[9px] font-mono">
      <span className="text-[var(--st-text-muted)] w-6 text-right uppercase">{label}</span>
      <div className="w-16 h-1.5 bg-[var(--st-bg-primary)] rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[var(--st-text-label)] w-12">
        {value}{unit}
      </span>
    </div>
  );
}

export function VMStats() {
  return (
    <div className="flex items-center gap-3 px-2 py-1 border-t border-[var(--st-border)] bg-[var(--st-bg-panel)] flex-shrink-0">
      <StatBar label="CPU" value={23} max={100} unit="%" color="bg-[var(--st-accent)]" />
      <StatBar label="RAM" value={156} max={512} unit="M" color="bg-[var(--st-severity-medium)]" />
      <StatBar label="NET" value={4} max={100} unit="KB" color="bg-[var(--st-severity-clean)]" />
    </div>
  );
}
```

**Step 4: Create VMZone.tsx**

```tsx
import { VMControls } from '../vm/VMControls';
import { VMTerminal } from '../vm/VMTerminal';
import { VMStats } from '../vm/VMStats';

export function VMZone() {
  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-panel)] border-l border-[var(--st-border)]">
      {/* Header */}
      <div className="flex items-center h-7 px-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">
          VM Sandbox
        </span>
      </div>

      <VMControls />
      <VMTerminal />
      <VMStats />
    </div>
  );
}
```

**Step 5: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 6: Commit**

```bash
git add src/renderer/src/components/vm/ src/renderer/src/components/workspace/VMZone.tsx
git commit -m "feat(wave3): add VMZone with controls, terminal output, and stat bars"
```

---

## Task 9: Data Panels — Network, IOC, Findings

**Files:**
- Create: `src/renderer/src/components/common/DataTable.tsx`
- Create: `src/renderer/src/components/panels/NetworkPanel.tsx`
- Create: `src/renderer/src/components/panels/IOCPanel.tsx`
- Create: `src/renderer/src/components/panels/FindingsPanel.tsx`

**Step 1: Create common/DataTable.tsx**

Generic data-dense sortable table matching the mockup's 28px row height.

```tsx
import { cn } from '../../lib/utils';

export interface Column<T> {
  key: string;
  label: string;
  width?: string;
  render?: (row: T, index: number) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyFn: (row: T, index: number) => string;
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export function DataTable<T>({ columns, data, keyFn, onRowClick, emptyMessage }: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
        {emptyMessage ?? 'No data'}
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full border-collapse text-[11px] font-mono">
        <thead className="sticky top-0 z-10">
          <tr className="bg-[var(--st-bg-panel)]">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] px-2 py-1.5 border-b border-[var(--st-border)]"
                style={col.width ? { width: col.width } : undefined}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr
              key={keyFn(row, i)}
              onClick={() => onRowClick?.(row)}
              className={cn(
                'h-7 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors',
                onRowClick && 'cursor-pointer',
              )}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-2 py-0 text-[var(--st-text-primary)] truncate max-w-0">
                  {col.render ? col.render(row, i) : String((row as Record<string, unknown>)[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

**Step 2: Create panels/NetworkPanel.tsx**

```tsx
import { useCallback, useMemo } from 'react';
import { DataTable, type Column } from '../common/DataTable';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import { ipcCall } from '../../ipc/bridge';
import type { HarLog, HarEntry } from '../../ipc/types';

function parseHarEntries(harString: string): HarEntry[] {
  if (!harString) return [];
  try {
    const har: HarLog = JSON.parse(harString);
    return har.log.entries.map((e) => ({
      method: e.request.method,
      url: e.request.url,
      status: e.response.status,
      size: e.response.content.size,
      time: e.time,
      mimeType: e.response.content.mimeType,
    }));
  } catch {
    return [];
  }
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}

function formatTime(ms: number): string {
  if (ms < 1000) return Math.round(ms) + 'ms';
  return (ms / 1000).toFixed(1) + 's';
}

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-[var(--st-severity-clean)]',
  POST: 'text-[var(--st-severity-medium)]',
  PUT: 'text-[var(--st-severity-medium)]',
  DELETE: 'text-[var(--st-severity-critical)]',
};

const COLUMNS: Column<HarEntry>[] = [
  {
    key: 'method',
    label: 'Method',
    width: '60px',
    render: (row) => (
      <span className={METHOD_COLORS[row.method] ?? 'text-[var(--st-text-label)]'}>
        {row.method}
      </span>
    ),
  },
  { key: 'url', label: 'URL' },
  {
    key: 'status',
    label: 'Status',
    width: '60px',
    render: (row) => {
      const severity = row.status >= 400 ? 'high' : row.status >= 300 ? 'medium' : 'clean';
      return <Badge severity={severity}>{row.status}</Badge>;
    },
  },
  {
    key: 'size',
    label: 'Size',
    width: '70px',
    render: (row) => <span className="text-[var(--st-text-label)]">{formatSize(row.size)}</span>,
  },
  {
    key: 'time',
    label: 'Time',
    width: '70px',
    render: (row) => <span className="text-[var(--st-text-label)]">{formatTime(row.time)}</span>,
  },
];

export function NetworkPanel() {
  const { captureData, capturing } = useStore();

  const entries = useMemo(
    () => parseHarEntries(captureData?.har ?? ''),
    [captureData?.har],
  );

  const toggleCapture = useCallback(async () => {
    if (capturing) {
      await ipcCall('stop_capture', { browser_id: 0 });
    } else {
      await ipcCall('start_capture', { browser_id: 0 });
    }
  }, [capturing]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">
          Network
        </span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">
          {entries.length}
        </span>
        <div className="flex-1" />
        <button
          onClick={toggleCapture}
          className="text-[9px] font-bold border-none bg-transparent cursor-pointer transition-colors px-1.5 py-0.5 rounded"
          style={{ color: capturing ? 'var(--st-severity-critical)' : 'var(--st-severity-clean)' }}
        >
          {capturing ? '■ STOP' : '● REC'}
        </button>
      </div>
      <DataTable
        columns={COLUMNS}
        data={entries}
        keyFn={(_, i) => String(i)}
        emptyMessage="No network requests captured"
      />
    </div>
  );
}
```

**Step 3: Create panels/IOCPanel.tsx**

```tsx
import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { SeverityLevel } from '../../ipc/types';

interface IOCEntry {
  value: string;
  type: 'domain' | 'ip' | 'hash' | 'url';
  source: string;
  severity: SeverityLevel;
}

function extractIOCs(findings: Array<{ metadata: Record<string, unknown>; severity: SeverityLevel }>): IOCEntry[] {
  const seen = new Set<string>();
  const iocs: IOCEntry[] = [];

  for (const f of findings) {
    const meta = f.metadata;
    const entries: Array<{ value: string; type: IOCEntry['type'] }> = [];

    if (typeof meta.domain === 'string') entries.push({ value: meta.domain, type: 'domain' });
    if (typeof meta.destination === 'string') entries.push({ value: meta.destination, type: 'ip' });
    if (typeof meta.path === 'string' && (meta.path as string).match(/^https?:\/\//)) entries.push({ value: meta.path as string, type: 'url' });

    for (const e of entries) {
      if (seen.has(e.value)) continue;
      seen.add(e.value);
      iocs.push({
        value: e.value,
        type: e.type,
        source: String(meta.mitre ?? 'analysis'),
        severity: f.severity,
      });
    }
  }
  return iocs;
}

const TYPE_ICONS: Record<string, string> = {
  domain: 'DNS',
  ip: 'IP',
  hash: 'HASH',
  url: 'URL',
};

const SOURCE_COLORS: Record<string, string> = {
  VT: 'bg-green-500/15 text-green-400',
  OTX: 'bg-purple-500/15 text-purple-400',
  Abuse: 'bg-red-500/15 text-red-400',
};

export function IOCPanel() {
  const { analysisResult, vmFindings } = useStore();

  const iocs = useMemo(() => {
    const allFindings = [
      ...(analysisResult?.verdict?.findings ?? []),
      ...vmFindings,
    ];
    return extractIOCs(allFindings);
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">IOC</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{iocs.length}</span>
      </div>
      <div className="flex-1 overflow-auto">
        {iocs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
            No indicators extracted
          </div>
        ) : (
          iocs.map((ioc, i) => (
            <div key={i} className="flex items-center gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <Badge severity={ioc.severity === 'critical' || ioc.severity === 'high' ? 'high' : 'info'} className="flex-shrink-0 w-9 justify-center">
                {TYPE_ICONS[ioc.type]}
              </Badge>
              <span className="text-[11px] font-mono text-[var(--st-text-primary)] truncate flex-1">
                {ioc.value}
              </span>
              <span className={`text-[8px] font-bold px-1 rounded ${SOURCE_COLORS[ioc.source] ?? 'bg-blue-500/15 text-blue-400'}`}>
                {ioc.source}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
```

**Step 4: Create panels/FindingsPanel.tsx**

```tsx
import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding } from '../../ipc/types';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function FindingsPanel() {
  const { analysisResult, vmFindings } = useStore();

  const findings = useMemo(() => {
    const all: Finding[] = [
      ...(analysisResult?.verdict?.findings ?? []),
      ...vmFindings,
    ];
    return all.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Findings</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{findings.length}</span>
      </div>
      <div className="flex-1 overflow-auto">
        {findings.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
            No findings yet
          </div>
        ) : (
          findings.map((f, i) => (
            <div key={i} className="px-2 py-1.5 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <div className="flex items-center gap-2">
                <Badge severity={f.severity}>{f.severity}</Badge>
                <span className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold">
                  {f.title}
                </span>
                <span className="text-[9px] text-[var(--st-text-muted)] ml-auto flex-shrink-0">
                  {f.engine}
                </span>
              </div>
              <div className="text-[10px] text-[var(--st-text-label)] mt-0.5 pl-0.5">
                {f.description}
              </div>
              {f.metadata.mitre && (
                <span className="inline-block mt-0.5 text-[8px] font-bold font-mono bg-[var(--st-accent)]/15 text-[var(--st-accent)] px-1 rounded">
                  {String(f.metadata.mitre)}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
```

**Step 5: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 6: Commit**

```bash
git add src/renderer/src/components/common/DataTable.tsx src/renderer/src/components/panels/NetworkPanel.tsx src/renderer/src/components/panels/IOCPanel.tsx src/renderer/src/components/panels/FindingsPanel.tsx
git commit -m "feat(wave3): add Network, IOC, and Findings data panels with DataTable"
```

---

## Task 10: Data Panels — MITRE, Activity, Sandbox, Process

**Files:**
- Create: `src/renderer/src/components/panels/MITREPanel.tsx`
- Create: `src/renderer/src/components/panels/ActivityPanel.tsx`
- Create: `src/renderer/src/components/panels/SandboxPanel.tsx`
- Create: `src/renderer/src/components/panels/ProcessPanel.tsx`
- Create: `src/renderer/src/components/panels/FilesPanel.tsx`
- Create: `src/renderer/src/components/panels/TimelinePanel.tsx`
- Create: `src/renderer/src/components/panels/ScreenshotsPanel.tsx`

**Step 1: Create panels/MITREPanel.tsx**

Extracts MITRE ATT&CK technique IDs from findings metadata and displays them as a compact grid.

```tsx
import { useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface MitreTechnique {
  id: string;
  title: string;
  severity: SeverityLevel;
  count: number;
}

function extractMitreTechniques(findings: Finding[]): MitreTechnique[] {
  const map = new Map<string, MitreTechnique>();

  for (const f of findings) {
    const id = String(f.metadata.mitre ?? '');
    if (!id) continue;

    const existing = map.get(id);
    if (existing) {
      existing.count++;
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      if (order.indexOf(f.severity) < order.indexOf(existing.severity)) {
        existing.severity = f.severity;
      }
    } else {
      map.set(id, { id, title: f.title, severity: f.severity, count: 1 });
    }
  }

  return Array.from(map.values()).sort((a, b) => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return order.indexOf(a.severity) - order.indexOf(b.severity);
  });
}

export function MITREPanel() {
  const { analysisResult, vmFindings } = useStore();

  const techniques = useMemo(() => {
    const all = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return extractMitreTechniques(all);
  }, [analysisResult, vmFindings]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">MITRE ATT&CK</span>
      </div>
      <div className="flex-1 overflow-auto p-2">
        {techniques.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
            No techniques mapped
          </div>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {techniques.map((t) => (
              <div
                key={t.id}
                className="flex items-center gap-1.5 px-2 py-1 rounded border border-[var(--st-border)] bg-[var(--st-bg-elevated)] hover:bg-[var(--st-bg-hover)] transition-colors cursor-default"
                title={`${t.id}: ${t.title}`}
              >
                <Badge severity={t.severity}>{t.id}</Badge>
                <span className="text-[10px] text-[var(--st-text-label)] max-w-32 truncate">
                  {t.title}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

**Step 2: Create panels/ActivityPanel.tsx**

Real-time event feed matching the mockup's timestamped activity log.

```tsx
import { useRef, useEffect, useMemo } from 'react';
import { Badge } from '../common/Badge';
import { useStore } from '../../store';
import type { Finding, SeverityLevel } from '../../ipc/types';

interface ActivityEvent {
  timestamp: string;
  icon: string;
  label: string;
  detail: string;
  severity: SeverityLevel;
}

function findingsToActivity(findings: Finding[]): ActivityEvent[] {
  const now = new Date();
  return findings.map((f, i) => {
    const ts = new Date(now.getTime() - (findings.length - i) * 1000);
    const timeStr = ts.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const icon = f.engine === 'yara' ? 'YARA' : f.engine === 'file_analysis' ? 'FILE' : f.engine === 'vm_sandbox' ? 'VM' : 'IOC';
    return { timestamp: timeStr, icon, label: f.title, detail: f.description, severity: f.severity };
  });
}

export function ActivityPanel() {
  const { analysisResult, vmFindings } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);

  const events = useMemo(() => {
    const all = [...(analysisResult?.verdict?.findings ?? []), ...vmFindings];
    return findingsToActivity(all);
  }, [analysisResult, vmFindings]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [events.length]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Activity</span>
        <span className="text-[9px] font-mono text-[var(--st-text-label)]">{events.length}</span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-auto">
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
            No activity yet
          </div>
        ) : (
          events.map((e, i) => (
            <div key={i} className="flex items-start gap-2 px-2 py-1 border-b border-[var(--st-border)]/50 hover:bg-[var(--st-bg-hover)] transition-colors">
              <span className="text-[9px] font-mono text-[var(--st-text-muted)] flex-shrink-0 pt-0.5">
                {e.timestamp}
              </span>
              <Badge severity={e.severity} className="flex-shrink-0 mt-0.5">{e.icon}</Badge>
              <div className="min-w-0">
                <div className="text-[11px] font-mono text-[var(--st-text-primary)] font-bold truncate">
                  {e.label}
                </div>
                <div className="text-[9px] text-[var(--st-text-label)] truncate">
                  {e.detail}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
```

**Step 3: Create panels/SandboxPanel.tsx**

```tsx
import { Badge } from '../common/Badge';
import { useStore } from '../../store';

export function SandboxPanel() {
  const { vmStatus, vmEvents, vmFindings, vmNetworkSummary } = useStore();

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Sandbox</span>
        <Badge severity={vmStatus === 'running' ? 'clean' : 'low'}>{vmStatus.toUpperCase()}</Badge>
      </div>
      <div className="flex-1 overflow-auto p-2 space-y-3">
        {/* Summary stats */}
        <div className="grid grid-cols-3 gap-2">
          <StatCard label="Events" value={vmEvents.length} />
          <StatCard label="Findings" value={vmFindings.length} />
          <StatCard label="DNS" value={vmNetworkSummary?.dns_query_count ?? 0} />
        </div>

        {/* Top findings */}
        {vmFindings.length > 0 && (
          <div>
            <div className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)] mb-1">Top Findings</div>
            {vmFindings.slice(0, 5).map((f, i) => (
              <div key={i} className="flex items-center gap-2 py-0.5">
                <Badge severity={f.severity}>{f.severity[0].toUpperCase()}</Badge>
                <span className="text-[10px] font-mono text-[var(--st-text-primary)] truncate">{f.title}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[var(--st-bg-elevated)] rounded border border-[var(--st-border)] p-2 text-center">
      <div className="text-[16px] font-bold font-mono text-[var(--st-text-primary)] glow">{value}</div>
      <div className="text-[8px] uppercase tracking-wider text-[var(--st-text-muted)]">{label}</div>
    </div>
  );
}
```

**Step 4: Create panels/ProcessPanel.tsx**

```tsx
import { useStore } from '../../store';
import type { ProcessNode } from '../../ipc/types';

function ProcessNodeRow({ node, depth }: { node: ProcessNode; depth: number }) {
  return (
    <>
      <div
        className="flex items-center gap-1 px-2 py-0.5 hover:bg-[var(--st-bg-hover)] transition-colors font-mono text-[11px]"
        style={{ paddingLeft: `${8 + depth * 16}px` }}
      >
        {node.children.length > 0 ? (
          <span className="text-[var(--st-text-muted)]">▸</span>
        ) : (
          <span className="text-[var(--st-border)] ml-1.5">·</span>
        )}
        <span className="text-[var(--st-severity-clean)]">{node.name}</span>
        <span className="text-[var(--st-text-muted)] text-[9px]">pid={node.pid}</span>
      </div>
      {node.children.map((child) => (
        <ProcessNodeRow key={child.pid} node={child} depth={depth + 1} />
      ))}
    </>
  );
}

export function ProcessPanel() {
  const { vmProcessTree } = useStore();

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Process Tree</span>
      </div>
      <div className="flex-1 overflow-auto">
        {vmProcessTree.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
            No processes observed
          </div>
        ) : (
          vmProcessTree.map((node) => (
            <ProcessNodeRow key={node.pid} node={node} depth={0} />
          ))
        )}
      </div>
    </div>
  );
}
```

**Step 5: Create panels/FilesPanel.tsx**

```tsx
export function FilesPanel() {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Files</span>
      </div>
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
        No files captured
      </div>
    </div>
  );
}
```

**Step 6: Create panels/TimelinePanel.tsx**

```tsx
export function TimelinePanel() {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Timeline</span>
      </div>
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
        No timeline events
      </div>
    </div>
  );
}
```

**Step 7: Create panels/ScreenshotsPanel.tsx**

```tsx
export function ScreenshotsPanel() {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Screenshots</span>
      </div>
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">
        No screenshots captured
      </div>
    </div>
  );
}
```

**Step 8: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 9: Commit**

```bash
git add src/renderer/src/components/panels/
git commit -m "feat(wave3): add MITRE, Activity, Sandbox, Process, Files, Timeline, Screenshots panels"
```

---

## Task 11: DataZone Component

**Files:**
- Create: `src/renderer/src/components/workspace/DataZone.tsx`

Bottom zone with tab bar (10 tabs in 3 groups) and up to 3 side-by-side sub-panels.

**Step 1: Create DataZone.tsx**

```tsx
import { useCallback, type ReactNode } from 'react';
import { cn } from '../../lib/utils';
import { CountBadge } from '../common/Badge';
import { useStore, type BottomTab } from '../../store';
import { NetworkPanel } from '../panels/NetworkPanel';
import { IOCPanel } from '../panels/IOCPanel';
import { ScreenshotsPanel } from '../panels/ScreenshotsPanel';
import { FilesPanel } from '../panels/FilesPanel';
import { SandboxPanel } from '../panels/SandboxPanel';
import { FindingsPanel } from '../panels/FindingsPanel';
import { MITREPanel } from '../panels/MITREPanel';
import { ActivityPanel } from '../panels/ActivityPanel';
import { TimelinePanel } from '../panels/TimelinePanel';
import { ProcessPanel } from '../panels/ProcessPanel';

interface TabDef {
  id: BottomTab;
  label: string;
  group: number;
}

const TABS: TabDef[] = [
  { id: 'network', label: 'Network', group: 0 },
  { id: 'ioc', label: 'IOC', group: 0 },
  { id: 'screenshots', label: 'Screenshots', group: 0 },
  { id: 'files', label: 'Files', group: 0 },
  { id: 'sandbox', label: 'Sandbox', group: 1 },
  { id: 'findings', label: 'Findings', group: 1 },
  { id: 'mitre', label: 'MITRE', group: 1 },
  { id: 'activity', label: 'Activity', group: 2 },
  { id: 'timeline', label: 'Timeline', group: 2 },
  { id: 'process', label: 'Process', group: 2 },
];

const PANEL_MAP: Record<BottomTab, () => ReactNode> = {
  network: () => <NetworkPanel />,
  ioc: () => <IOCPanel />,
  screenshots: () => <ScreenshotsPanel />,
  files: () => <FilesPanel />,
  sandbox: () => <SandboxPanel />,
  findings: () => <FindingsPanel />,
  mitre: () => <MITREPanel />,
  activity: () => <ActivityPanel />,
  timeline: () => <TimelinePanel />,
  process: () => <ProcessPanel />,
};

export function DataZone() {
  const { bottomTabs, bottomPrimaryTab, setBottomPrimaryTab } = useStore();

  const onTabClick = useCallback((tabId: BottomTab) => {
    setBottomPrimaryTab(tabId);
  }, [setBottomPrimaryTab]);

  let prevGroup = -1;

  return (
    <div className="flex flex-col h-full bg-[var(--st-bg-panel)] border-t border-[var(--st-border)]">
      {/* Tab bar */}
      <div className="flex items-center h-7 px-2 gap-0.5 border-b border-[var(--st-border)] flex-shrink-0 overflow-x-auto">
        {TABS.map((tab) => {
          const showSep = prevGroup >= 0 && tab.group !== prevGroup;
          prevGroup = tab.group;
          const isActive = bottomTabs.includes(tab.id);
          const isPrimary = tab.id === bottomPrimaryTab;

          return (
            <span key={tab.id} className="flex items-center">
              {showSep && <span className="text-[var(--st-border)] mx-1 select-none text-[10px]">|</span>}
              <button
                onClick={() => onTabClick(tab.id)}
                className={cn(
                  'px-2 py-1 rounded text-[10px] font-medium border-none cursor-pointer transition-colors whitespace-nowrap flex items-center gap-1',
                  isPrimary
                    ? 'bg-[var(--st-accent-dim)] text-[var(--st-accent)]'
                    : isActive
                      ? 'bg-transparent text-[var(--st-text-label)]'
                      : 'bg-transparent text-[var(--st-text-muted)] hover:text-[var(--st-text-label)] hover:bg-[var(--st-bg-hover)]',
                )}
              >
                {tab.label}
                {isActive && <CountBadge count={0} color="blue" />}
              </button>
            </span>
          );
        })}
      </div>

      {/* Sub-panels — show bottomTabs[0..2] side by side */}
      <div className="flex-1 flex overflow-hidden">
        {bottomTabs.map((tabId, i) => (
          <div
            key={tabId}
            className={cn(
              'flex-1 min-w-0 overflow-hidden',
              i < bottomTabs.length - 1 && 'border-r border-[var(--st-border)]',
            )}
          >
            {PANEL_MAP[tabId]()}
          </div>
        ))}
      </div>
    </div>
  );
}
```

**Step 2: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 3: Commit**

```bash
git add src/renderer/src/components/workspace/DataZone.tsx
git commit -m "feat(wave3): add DataZone with 10-tab bar and 3-panel split layout"
```

---

## Task 12: WorkspaceRoot + App.tsx Integration

**Files:**
- Create: `src/renderer/src/components/workspace/WorkspaceRoot.tsx`
- Modify: `src/renderer/src/App.tsx`

**Step 1: Create WorkspaceRoot.tsx**

Wires all zones together: IconRail | (TopBar + top row + H-splitter + bottom row).

```tsx
import { useCallback, useRef } from 'react';
import { TopBar } from './TopBar';
import { IconRail } from './IconRail';
import { BrowserZone } from './BrowserZone';
import { VMZone } from './VMZone';
import { DataZone } from './DataZone';
import { SplitterH } from './SplitterH';
import { SplitterV } from './SplitterV';
import { useStore } from '../../store';

export function WorkspaceRoot() {
  const { topSplit, mainSplit, vmCollapsed, setTopSplit, setMainSplit } = useStore();
  const containerRef = useRef<HTMLDivElement>(null);

  const onHSplitterDrag = useCallback((deltaY: number) => {
    const container = containerRef.current;
    if (!container) return;
    const totalHeight = container.clientHeight - 40; // subtract TopBar
    setMainSplit(mainSplit + deltaY / totalHeight);
  }, [mainSplit, setMainSplit]);

  const onVSplitterDrag = useCallback((deltaX: number) => {
    const container = containerRef.current;
    if (!container) return;
    const totalWidth = container.clientWidth - 52; // subtract IconRail
    setTopSplit(topSplit + deltaX / totalWidth);
  }, [topSplit, setTopSplit]);

  const topPct = `${mainSplit * 100}%`;
  const bottomPct = `${(1 - mainSplit) * 100}%`;
  const leftPct = vmCollapsed ? '100%' : `${topSplit * 100}%`;
  const rightPct = vmCollapsed ? '0%' : `${(1 - topSplit) * 100}%`;

  return (
    <div className="h-screen w-screen flex overflow-hidden">
      {/* Icon Rail */}
      <IconRail />

      {/* Main content */}
      <div ref={containerRef} className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <TopBar />

        {/* Top row */}
        <div className="flex min-h-0" style={{ height: topPct }}>
          {/* Browser zone */}
          <div className="min-w-0 overflow-hidden" style={{ width: leftPct }}>
            <BrowserZone />
          </div>

          {/* V-splitter + VM zone */}
          {!vmCollapsed && (
            <>
              <SplitterV onDrag={onVSplitterDrag} />
              <div className="min-w-0 overflow-hidden" style={{ width: rightPct }}>
                <VMZone />
              </div>
            </>
          )}
        </div>

        {/* H-splitter */}
        <SplitterH onDrag={onHSplitterDrag} />

        {/* Bottom row — Data zone */}
        <div className="min-h-0 overflow-hidden" style={{ height: bottomPct }}>
          <DataZone />
        </div>
      </div>
    </div>
  );
}
```

**Step 2: Update App.tsx**

Replace the stub with WorkspaceRoot.

```tsx
import { WorkspaceRoot } from './components/workspace/WorkspaceRoot';

export function App() {
  return <WorkspaceRoot />;
}
```

**Step 3: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build producing dist/ with all assets

**Step 4: Verify dev server renders**

Run: `cd src/renderer && npx vite --open`
Expected: Browser opens to localhost:5173 showing the full multi-zone layout with Phantom Terminal theme — green on black, icon rail on left, browser zone top-left, VM zone top-right, data zone bottom with tabs.

**Step 5: Commit**

```bash
git add src/renderer/src/components/workspace/WorkspaceRoot.tsx src/renderer/src/App.tsx
git commit -m "feat(wave3): wire WorkspaceRoot — complete multi-zone layout with all panels"
```

---

## Task 13: IPC Hooks + Polling

**Files:**
- Create: `src/renderer/src/hooks/useIpc.ts`
- Create: `src/renderer/src/hooks/useAnalysis.ts`
- Create: `src/renderer/src/hooks/useCapture.ts`

**Step 1: Create hooks/useIpc.ts**

```typescript
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
```

**Step 2: Create hooks/useAnalysis.ts**

```typescript
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
```

**Step 3: Create hooks/useCapture.ts**

```typescript
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
```

**Step 4: Verify build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build

**Step 5: Commit**

```bash
git add src/renderer/src/hooks/
git commit -m "feat(wave3): add IPC hooks — useIpc, useAnalysisPolling, useCapturePolling"
```

---

## Task 14: Font Assets + Final Build Verification

**Files:**
- Create: `src/renderer/public/fonts/` directory with JetBrains Mono woff2
- Verify: Complete production build

**Step 1: Download JetBrains Mono font**

Run: `mkdir -p src/renderer/public/fonts && curl -L -o src/renderer/public/fonts/JetBrainsMono-Variable.woff2 "https://github.com/JetBrains/JetBrainsMono/raw/master/fonts/variable/JetBrainsMono%5Bwght%5D.woff2"`

If the download fails, the CSS font-face will gracefully fall back to `Fira Code` → `Cascadia Code` → system monospace. The font asset is optional.

**Step 2: Final production build**

Run: `cd src/renderer && npx vite build`
Expected: Clean build. Output summary shows:
- `dist/index.html`
- `dist/assets/*.js` (bundled React app)
- `dist/assets/*.css` (bundled Tailwind styles)

**Step 3: Verify dev server renders correctly**

Run: `cd src/renderer && npx vite --open`
Expected: Full Phantom Terminal UI visible:
- Green-on-black theme with scanline overlay
- 52px icon rail on left with BRW/EML/MAL/LOG presets
- TopBar with SHIELDTIER logo and CLEAN badge
- Browser zone top-left with URL bar and SANDBOXED badge
- VM zone top-right with controls, terminal, stat bars
- Horizontal splitter between top and bottom
- Bottom data zone with 10 tabs showing Network + IOC + Activity panels

**Step 4: Commit**

```bash
git add src/renderer/public/
git commit -m "feat(wave3): add font assets and verify final build"
```

---

## Task Summary

| Task | Description | Files Created |
|------|-------------|---------------|
| 1 | Project scaffold | 6 (package.json, vite, ts, html, main, App) |
| 2 | Theme + utilities | 5 (globals.css, utils, Badge, StatusDot, Panel) |
| 3 | IPC bridge + store | 3 (bridge, types, store) |
| 4 | Splitters | 2 (SplitterH, SplitterV) |
| 5 | TopBar | 1 |
| 6 | IconRail | 1 |
| 7 | BrowserZone | 1 |
| 8 | VMZone | 4 (VMControls, VMTerminal, VMStats, VMZone) |
| 9 | Data panels batch 1 | 4 (DataTable, NetworkPanel, IOCPanel, FindingsPanel) |
| 10 | Data panels batch 2 | 7 (MITRE, Activity, Sandbox, Process, Files, Timeline, Screenshots) |
| 11 | DataZone | 1 |
| 12 | WorkspaceRoot + App | 2 |
| 13 | IPC hooks | 3 (useIpc, useAnalysis, useCapture) |
| 14 | Font assets + final build | 1 (font file) |

**Total: 14 tasks, ~41 files, 14 commits**
