# Wave 3 — Phantom Terminal UI Design

**Date:** 2026-03-03
**Status:** Draft
**Reference:** V1 `v2-workspace-redesign` branch design doc + mockup

## Problem

The native C++ backend (Waves 0-2) has 13 analysis engines, IPC message routing, VM sandbox orchestration, and network capture — but no UI to drive it. We need a React renderer that CEF loads, giving analysts a multi-zone workspace matching ANY.RUN's data density.

## Design Goals

1. **Multi-zone layout** — browser, live VM, and data panels visible simultaneously
2. **Hacker terminal vibe** — Matrix-green on black, monospace everywhere, data-dense, minimal chrome
3. **ANY.RUN parity** — real-time behavioral events, process trees, network capture, MITRE mapping
4. **CefMessageRouter IPC** — all communication via `window.cefQuery()` JSON bridge
5. **Layout presets** — BRW/EML/MAL/LOG for workflow-specific zone configurations

## Stack

- React 19 + TypeScript 5.7
- Tailwind CSS 4 (Vite plugin)
- Radix UI (headless primitives)
- Zustand (state management)
- Vite 6 (bundler, builds to `src/renderer/dist/`)
- JetBrains Mono (monospace font)

## Layout Architecture

```
+------+-----------------------------------------------------+
| ICON |  TopBar (40px) — Logo | Case | Status | REC | SOCKS |
| RAIL +---------------------------+--------------------------+
| 52px |  Browser Zone (flex 1.2)  |  VM Sandbox Zone (flex 1)|
|      |  URL bar + SANDBOXED      |  OS select + RUNNING     |
| BRW  |  [iframe/CEF view]        |  Terminal output          |
| EML  |                           |  Files + controls        |
| MAL  |                           |  CPU/RAM/NET bars        |
| LOG  +===========================+==========================+
|      |  H-SPLITTER (5px drag handle)                        |
| YARA +------------------------------------------------------+
| FEED |  Data Zone — Tab bar + Sub-panels                    |
|      |  [Network|IOC|Screenshots|Files|Sandbox|Findings|    |
|      |   MITRE|Activity|Timeline|Process]                   |
| REC  |  +--------------+-----------+------------------+     |
|      |  | Sub-panel 1  | Sub-p. 2  | Sub-panel 3     |     |
+------+--+--------------+-----------+------------------+-----+
```

### Icon Rail (52px)

Replaces traditional sidebar. Contains:
- **Cases** button (opens session list as flyout overlay)
- **Layout presets**: BRW / EML / MAL / LOG toggle buttons
- **Quick access**: YARA (with rule count badge), Feeds (with indicator count badge)
- **Bottom**: REC indicator, Report export, Screenshot

### Layout Presets

| Preset | Top Left | Top Right | Bottom Default | Use Case |
|--------|----------|-----------|---------------|----------|
| BRW | Browser | VM Sandbox | Network + IOC + Activity | Web investigation |
| EML | Email viewer | (collapsed) | Headers + IOC + Findings | Phishing analysis |
| MAL | Browser | VM Sandbox | Sandbox + Files + MITRE | Malware analysis |
| LOG | Log viewer | (collapsed) | Timeline + Activity + Process | Log investigation |

### Top Row — Two Zones

**Left Zone: Primary Input** (flex 1.2)
- Browser tab (default): URL bar with SANDBOXED badge + embedded web view
- Email tab: EML/raw email viewer
- Logs tab: Log import + analysis

**Right Zone: Live VM Sandbox** (flex 1)
- OS selector dropdown (Alpine/ReactOS/Windows)
- Start/Stop controls + CPU/RAM/NET stat bars
- Terminal output panel (behavioral events from VM agent)
- Files panel (submitted samples with status icons)
- "LIVE - ANALYZING" badge overlay

### Bottom Row — Data Zone

Tab bar with 10 tabs in 3 logical groups:
1. **Capture**: Network, IOC, Screenshots, Files
2. **Analysis**: Sandbox, Findings, MITRE
3. **Timeline**: Activity, Timeline, Process

Active tab content can display up to 3 sub-panels side by side. Default BRW preset shows Network + IOC + Activity simultaneously.

## Visual Theme — "Phantom Terminal"

```css
:root {
  --st-bg-primary: #0a0a0a;
  --st-bg-panel: #0f1117;
  --st-bg-elevated: #151921;
  --st-border: #1c2030;
  --st-text-primary: #00ff41;
  --st-text-secondary: #00cc33;
  --st-text-muted: #2d5a35;
  --st-accent: #3b82f6;
  --st-accent-dim: rgba(59, 130, 246, 0.1);
  --st-severity-critical: #ff0040;
  --st-severity-high: #ff6600;
  --st-severity-medium: #ffcc00;
  --st-severity-low: #00ccff;
  --st-severity-clean: #00ff41;
  --st-font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --st-font-ui: 'Inter', system-ui, sans-serif;
}
```

- All data values in monospace (`--st-font-mono`)
- UI labels in Inter (`--st-font-ui`) at 11px
- Subtle scanline overlay (CSS repeating-linear-gradient, 1px/3px)
- Glow on focused elements: `text-shadow: 0 0 6px var(--st-text-primary)`
- Data-dense tables: 28px rows, tight padding
- Severity badges: red/orange/yellow/blue/green with 15% opacity backgrounds
- Glass morphism on TopBar and IconRail: `backdrop-filter: blur(12px)`

## IPC Bridge

```typescript
// src/renderer/src/ipc/bridge.ts
export function ipcCall<T>(action: string, payload: Record<string, unknown> = {}): Promise<T> {
  return new Promise((resolve, reject) => {
    window.cefQuery({
      request: JSON.stringify({ action, payload }),
      onSuccess: (response: string) => {
        const parsed = JSON.parse(response);
        if (parsed.success) resolve(parsed.data as T);
        else reject(new Error(parsed.error));
      },
      onFailure: (_code: number, message: string) => reject(new Error(message)),
    });
  });
}
```

Maps to native IPC actions: `navigate`, `get_tabs`, `close_tab`, `analyze_download`, `get_analysis_result`, `get_config`, `set_config`, `export_report`, `get_threat_feeds`, `start_capture`, `stop_capture`, `get_capture`.

## Source Tree

```
src/renderer/
  index.html
  package.json
  vite.config.ts
  tailwind.config.ts
  tsconfig.json
  public/
    fonts/                  <- JetBrains Mono woff2
  src/
    main.tsx
    App.tsx
    globals.css             <- Theme vars, scanline overlay, base styles
    ipc/
      bridge.ts             <- window.cefQuery() wrapper
      types.ts              <- IPC request/response TypeScript types
    store/
      index.ts              <- Zustand store
    components/
      workspace/
        WorkspaceRoot.tsx   <- Root multi-zone layout with splitters
        IconRail.tsx        <- 52px sidebar with presets
        TopBar.tsx          <- Case info, status, REC, SOCKS
        BrowserZone.tsx     <- URL bar + embedded web view
        VMZone.tsx          <- VM controls + terminal + files
        DataZone.tsx        <- Bottom tab bar + sub-panels
        SplitterH.tsx       <- Horizontal resize handle
        SplitterV.tsx       <- Vertical resize handle
      panels/
        NetworkPanel.tsx    <- Request table + HAR
        IOCPanel.tsx        <- Indicators of compromise
        FindingsPanel.tsx   <- Analysis findings with severity
        MITREPanel.tsx      <- ATT&CK technique grid
        ActivityPanel.tsx   <- Real-time event feed
        SandboxPanel.tsx    <- VM behavioral results
        FilesPanel.tsx      <- Captured/uploaded files
        ProcessPanel.tsx    <- Process tree view
        TimelinePanel.tsx   <- Chronological event timeline
        ScreenshotsPanel.tsx
      vm/
        VMTerminal.tsx      <- Agent output terminal
        VMFiles.tsx         <- Submitted sample list
        VMControls.tsx      <- Start/Stop/OS selector
        VMStats.tsx         <- CPU/RAM/NET bars
      common/
        Badge.tsx           <- Severity/status badges
        DataTable.tsx       <- Compact sortable table
        Panel.tsx           <- Panel wrapper with header
        StatusDot.tsx       <- Animated status indicator
    hooks/
      useIpc.ts             <- Generic IPC query hook
      useAnalysis.ts        <- Analysis polling
      useCapture.ts         <- Network capture state
      useVm.ts              <- VM sandbox state
    lib/
      utils.ts              <- cn() classname merge
```

## State Management (Zustand)

```typescript
interface ShieldTierStore {
  // Layout
  preset: 'brw' | 'eml' | 'mal' | 'log';
  topSplit: number;         // 0-1, vertical split (browser vs VM)
  mainSplit: number;        // 0-1, horizontal split (top vs bottom)
  vmCollapsed: boolean;
  activeTopLeft: 'browser' | 'email' | 'logs';
  activeBottomTabs: string[];
  bottomPrimaryTab: string;

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
  vmStatus: 'idle' | 'booting' | 'running' | 'complete';
  vmEvents: VmEvent[];
  vmFindings: Finding[];
  vmProcessTree: ProcessNode[];
  vmNetworkActivity: NetworkSummary | null;

  // Config
  config: Record<string, unknown>;
}
```

## Key Components

| Component | Purpose | IPC Actions |
|-----------|---------|------------|
| TopBar | Case ID, name, REC timer, SOCKS proxy, threat status | — |
| IconRail | Layout presets, session flyout, YARA/feed badges | get_config |
| BrowserZone | URL bar + navigation + embedded view | navigate |
| VMZone | OS select, controls, terminal, files | (future VM IPC) |
| NetworkPanel | HTTP request table with method/url/status/size/time | start_capture, stop_capture, get_capture |
| IOCPanel | Extracted IOCs with source tags (VT, OTX, Abuse) | get_analysis_result |
| FindingsPanel | Severity-sorted findings from all engines | get_analysis_result |
| MITREPanel | ATT&CK technique grid from findings metadata | get_analysis_result |
| ActivityPanel | Timestamped event feed (IOC, YARA, download, screenshot) | get_analysis_result |
| SandboxPanel | VM behavioral analysis summary | get_analysis_result |
| ProcessPanel | Process tree from VM events | (from VM events) |

## Data Flow

```
User enters URL → BrowserZone → ipcCall("navigate", {url})
                               → C++ loads URL in CEF
                               → CefResponseFilter captures response
                               → Download intercepted → auto-analyze

Analysis polling → ipcCall("get_analysis_result", {sha256})
                 → {status, verdict: {score, severity, findings[]}}
                 → Store updates → panels re-render

Network capture → ipcCall("start_capture", {browser_id})
               → User browses → ipcCall("get_capture") polling
               → {capturing, request_count, har}
               → NetworkPanel renders request table

VM sandbox → VM events via protocol
           → VMTerminal shows real-time output
           → ActivityPanel shows timestamped events
           → ProcessPanel builds tree
           → MITREPanel maps findings to techniques
```

## Build Configuration

CEF loads `file:///path/to/src/renderer/dist/index.html`. Vite builds with `base: './'` for relative asset paths. During development, `vite dev` on port 5173 with IPC bridge stubbed for testing without CEF.

## Verification

1. `npm run build` in src/renderer/ produces dist/ with index.html
2. Multi-zone layout renders: top-left browser, top-right VM, bottom data
3. Icon rail shows BRW/EML/MAL/LOG presets, switching reconfigures zones
4. H-splitter resizes top/bottom ratio
5. V-splitter resizes browser/VM ratio
6. URL bar dispatches navigate IPC
7. Network tab shows capture data
8. Activity feed shows timestamped events
9. All severity badges render with correct colors
10. Phantom Terminal theme: green-on-black, monospace, scanlines, glow
