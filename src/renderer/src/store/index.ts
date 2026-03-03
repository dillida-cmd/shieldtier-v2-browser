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
  preset: LayoutPreset;
  topSplit: number;
  mainSplit: number;
  vmCollapsed: boolean;
  activeTopLeft: TopLeftTab;
  bottomTabs: [BottomTab, BottomTab, BottomTab];
  bottomPrimaryTab: BottomTab;

  caseId: string;
  caseName: string;

  currentSha256: string | null;
  analysisStatus: 'idle' | 'pending' | 'complete' | 'error';
  analysisResult: AnalysisResult | null;

  capturing: boolean;
  captureData: CaptureData | null;

  vmStatus: VmStatus;
  vmEvents: VmEvent[];
  vmFindings: Finding[];
  vmProcessTree: ProcessNode[];
  vmNetworkSummary: NetworkSummary | null;

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
  preset: 'brw',
  topSplit: 0.55,
  mainSplit: 0.57,
  vmCollapsed: false,
  activeTopLeft: 'browser',
  bottomTabs: ['network', 'ioc', 'activity'],
  bottomPrimaryTab: 'network',

  caseId: '',
  caseName: '',

  currentSha256: null,
  analysisStatus: 'idle',
  analysisResult: null,

  capturing: false,
  captureData: null,

  vmStatus: 'idle',
  vmEvents: [],
  vmFindings: [],
  vmProcessTree: [],
  vmNetworkSummary: null,

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
