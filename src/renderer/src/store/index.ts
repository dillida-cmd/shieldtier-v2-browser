import { create } from 'zustand';
import type {
  AnalysisResult,
  CaptureData,
  DownloadInfo,
  FileEntry,
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

export type ModalState = 'none' | 'command' | 'settings' | 'export' | 'caseName';
export type ThemeMode = 'dark' | 'light';
export type FontSize = 'sm' | 'md' | 'lg';

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

  navCanGoBack: boolean;
  navCanGoForward: boolean;
  navIsLoading: boolean;
  navCurrentUrl: string;
  navTitle: string;
  currentDownload: DownloadInfo | null;

  screenshots: string[];
  capturedFiles: FileEntry[];
  vmCpuPct: number;
  vmRamMb: number;
  vmNetKbps: number;

  chatIdentity: { sessionId: string; publicKey: string } | null;
  chatContacts: Array<{ id: string; name: string; status: string; unread: number }>;
  chatMessages: Record<string, Array<{ id: string; from: string; text: string; timestamp: number; read: boolean }>>;
  chatPresence: Record<string, 'online' | 'offline' | 'away'>;
  chatConnectionStatus: 'connected' | 'disconnected' | 'connecting';
  chatActiveContact: string | null;

  modalState: ModalState;
  theme: ThemeMode;
  fontSize: FontSize;

  setModalState: (state: ModalState) => void;
  setTheme: (theme: ThemeMode) => void;
  setFontSize: (size: FontSize) => void;
  setCaseInfo: (id: string, name: string) => void;
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
  setNavState: (state: { can_back: boolean; can_forward: boolean; loading: boolean; url: string; title: string }) => void;
  setCurrentDownload: (info: DownloadInfo | null) => void;
  setCurrentSha256: (sha256: string) => void;
  addScreenshot: (url: string) => void;
  addCapturedFile: (file: FileEntry) => void;
  setCapturedFiles: (files: FileEntry[]) => void;
  setVmStats: (cpu: number, ram: number, net: number) => void;

  setChatIdentity: (identity: { sessionId: string; publicKey: string } | null) => void;
  setChatContacts: (contacts: Array<{ id: string; name: string; status: string; unread: number }>) => void;
  addChatMessage: (contactId: string, message: { id: string; from: string; text: string; timestamp: number; read: boolean }) => void;
  setChatPresence: (contactId: string, presence: 'online' | 'offline' | 'away') => void;
  setChatConnectionStatus: (status: 'connected' | 'disconnected' | 'connecting') => void;
  setChatActiveContact: (contactId: string | null) => void;
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

  navCanGoBack: false,
  navCanGoForward: false,
  navIsLoading: false,
  navCurrentUrl: '',
  navTitle: '',
  currentDownload: null,

  screenshots: [],
  capturedFiles: [],
  vmCpuPct: 0,
  vmRamMb: 0,
  vmNetKbps: 0,

  chatIdentity: null,
  chatContacts: [],
  chatMessages: {},
  chatPresence: {},
  chatConnectionStatus: 'disconnected',
  chatActiveContact: null,

  modalState: 'none',
  theme: 'dark',
  fontSize: 'md',

  setModalState: (modalState) => set({ modalState }),
  setTheme: (theme) => set({ theme }),
  setFontSize: (fontSize) => set({ fontSize }),
  setCaseInfo: (caseId, caseName) => set({ caseId, caseName }),
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
    analysisStatus: result.status === 'complete' ? 'complete' : (result.status === 'error' || result.status === 'not_found') ? 'error' : 'pending',
    analysisResult: result,
  }),
  setCaptureData: (captureData) => set({ captureData }),
  setCapturing: (capturing) => set({ capturing }),
  setVmStatus: (vmStatus) => set({ vmStatus }),
  addVmEvent: (event) => set((s) => ({ vmEvents: [...s.vmEvents, event] })),
  setVmFindings: (vmFindings) => set({ vmFindings }),
  setVmProcessTree: (vmProcessTree) => set({ vmProcessTree }),
  setVmNetworkSummary: (vmNetworkSummary) => set({ vmNetworkSummary }),
  setNavState: (state) => set({
    navCanGoBack: state.can_back,
    navCanGoForward: state.can_forward,
    navIsLoading: state.loading,
    navCurrentUrl: state.url,
    navTitle: state.title,
  }),
  setCurrentDownload: (currentDownload) => set({ currentDownload }),
  setCurrentSha256: (sha256) => set({
    currentSha256: sha256,
    analysisStatus: 'pending',
    analysisResult: null,
  }),
  addScreenshot: (url) => set((s) => ({ screenshots: [...s.screenshots, url] })),
  addCapturedFile: (file) => set((s) => ({ capturedFiles: [...s.capturedFiles, file] })),
  setCapturedFiles: (capturedFiles) => set({ capturedFiles }),
  setVmStats: (vmCpuPct, vmRamMb, vmNetKbps) => set({ vmCpuPct, vmRamMb, vmNetKbps }),

  setChatIdentity: (chatIdentity) => set({ chatIdentity }),
  setChatContacts: (chatContacts) => set({ chatContacts }),
  addChatMessage: (contactId, message) => set((s) => ({
    chatMessages: {
      ...s.chatMessages,
      [contactId]: [...(s.chatMessages[contactId] ?? []), message],
    },
  })),
  setChatPresence: (contactId, presence) => set((s) => ({
    chatPresence: { ...s.chatPresence, [contactId]: presence },
  })),
  setChatConnectionStatus: (chatConnectionStatus) => set({ chatConnectionStatus }),
  setChatActiveContact: (chatActiveContact) => set({ chatActiveContact }),
}));
