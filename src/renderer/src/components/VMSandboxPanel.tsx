/**
 * VMSandboxPanel — main VM sandbox UI.
 *
 * 3 views:
 *   1. Setup Required → VMSetupWizard
 *   2. Ready → file picker, OS selector, timeout, "Run in VM" button
 *   3. Active → live event stream, status, screenshots, abort
 *   4. Results → 6-tab report (Summary/Processes/Behaviors/Network/Files/Registry)
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import VMSetupWizard from './VMSetupWizard';

// Types matching main process
interface VMStatusUpdate {
  instanceId: string;
  sessionId: string;
  status: string;
  event?: { type: string; timestamp: number; data: Record<string, any> };
  progress?: string;
  error?: string;
}

interface VMAnalysisResult {
  instanceId: string;
  verdict: string;
  score: number;
  riskLevel: string;
  executionDurationMs: number;
  processTree: any[];
  processCount: number;
  fileOperations: any[];
  registryOperations: any[];
  networkConnections: any[];
  memoryAllocations: any[];
  screenshots: { timestamp: number; data: string }[];
  findings: { severity: string; category: string; description: string; mitre?: string }[];
  networkSummary: {
    totalConnections: number;
    uniqueHosts: string[];
    uniqueURLs: string[];
    dnsQueries: { hostname: string; ip: string }[];
    httpRequests: number;
  };
  mitreTechniques: string[];
}

interface VMSandboxPanelProps {
  session: { id: string };
  files: Map<string, any>;
}

type VMView = 'checking' | 'setup' | 'ready' | 'active' | 'results';
type ResultTab = 'summary' | 'processes' | 'behaviors' | 'network' | 'files' | 'registry';

/**
 * Parse PPM (P6 binary) data from base64 and render to canvas.
 * QEMU screendump outputs P6 PPM: "P6\n{width} {height}\n{maxval}\n{RGB bytes}"
 */
function renderPPMToCanvas(canvas: HTMLCanvasElement, base64Data: string): void {
  try {
    const binary = atob(base64Data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    // Parse PPM header: "P6\n<width> <height>\n<maxval>\n"
    let offset = 0;
    const readLine = (): string => {
      let line = '';
      while (offset < bytes.length) {
        const ch = bytes[offset++];
        if (ch === 0x0A) break; // newline
        line += String.fromCharCode(ch);
      }
      return line.trim();
    };

    const magic = readLine();
    if (magic !== 'P6') return;

    // Skip comments
    let dimensions = readLine();
    while (dimensions.startsWith('#')) {
      dimensions = readLine();
    }

    const parts = dimensions.split(/\s+/);
    const width = parseInt(parts[0], 10);
    const height = parseInt(parts[1], 10);
    if (!width || !height) return;

    readLine(); // maxval (usually 255)

    // Set canvas size and scale to fit container
    canvas.width = width;
    canvas.height = height;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const imageData = ctx.createImageData(width, height);
    const pixels = imageData.data;
    const rgbData = bytes.subarray(offset);

    for (let i = 0; i < width * height; i++) {
      const srcIdx = i * 3;
      const dstIdx = i * 4;
      pixels[dstIdx] = rgbData[srcIdx];       // R
      pixels[dstIdx + 1] = rgbData[srcIdx + 1]; // G
      pixels[dstIdx + 2] = rgbData[srcIdx + 2]; // B
      pixels[dstIdx + 3] = 255;                 // A
    }

    ctx.putImageData(imageData, 0, 0);
  } catch {
    // PPM parsing failed — skip this frame
  }
}

const VERDICT_COLORS: Record<string, string> = {
  malicious: 'text-red-400 bg-red-500/20 border-red-500/30',
  suspicious: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
  clean: 'text-green-400 bg-green-500/20 border-green-500/30',
  unknown: 'text-gray-400 bg-gray-500/20 border-gray-500/30',
};

export default function VMSandboxPanel({ session, files }: VMSandboxPanelProps) {
  const [view, setView] = useState<VMView>('checking');
  const [qemuReady, setQemuReady] = useState(false);
  const [selectedFileId, setSelectedFileId] = useState<string>('');
  const [selectedOS, setSelectedOS] = useState<'windows' | 'linux'>('linux');
  const [selectedImageId, setSelectedImageId] = useState('alpine-3.19');
  const [timeout, setTimeoutSec] = useState(120);
  const [images, setImages] = useState<any[]>([]);

  // Active execution state
  const [vmStatus, setVmStatus] = useState<string>('');
  const [vmProgress, setVmProgress] = useState<string>('');
  const [vmInstanceId, setVmInstanceId] = useState<string | null>(null);
  const [events, setEvents] = useState<VMStatusUpdate[]>([]);
  const [liveError, setLiveError] = useState<string | null>(null);

  // Results state
  // Results state
  const [result, setResult] = useState<VMAnalysisResult | null>(null);
  const [activeResultTab, setActiveResultTab] = useState<ResultTab>('summary');

  // Snapshot state
  const [snapshotReady, setSnapshotReady] = useState<Record<string, boolean>>({});
  const [preparingSnapshot, setPreparingSnapshot] = useState<string | null>(null);
  const [snapshotMessage, setSnapshotMessage] = useState<string>('');

  // Image download state
  const [showImageManager, setShowImageManager] = useState(false);
  const [downloadingImageId, setDownloadingImageId] = useState<string | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<{ percent: number; downloadedMB: number; totalMB: number } | null>(null);

  const eventLogRef = useRef<HTMLDivElement>(null);
  const vmCanvasRef = useRef<HTMLCanvasElement>(null);
  const [latestScreenshot, setLatestScreenshot] = useState<string | null>(null);

  // Check QEMU on mount + restore any existing results
  useEffect(() => {
    checkSetup().then(async () => {
      // Restore results from a previous run in this session
      try {
        const vm = (window as any).shieldtier?.vm;
        if (!vm?.getInstances) return;
        const instances = await vm.getInstances(session.id);
        if (!instances || instances.length === 0) return;

        // Find the most recent completed or running instance
        const sorted = [...instances].sort((a: any, b: any) => (b.startedAt || 0) - (a.startedAt || 0));
        const latest = sorted[0];

        if (latest.status === 'completed' && latest.result) {
          setResult(latest.result);
          setVmInstanceId(latest.id);
          setView('results');
        } else if (['preparing', 'booting', 'injecting', 'executing', 'collecting'].includes(latest.status)) {
          setVmInstanceId(latest.id);
          setVmStatus(latest.status);
          setView('active');
        }
      } catch {}
    }).catch(() => setView('setup'));
  }, [session.id]);

  // Listen for VM status updates
  useEffect(() => {
    try {
      const vm = (window as any).shieldtier?.vm;
      if (!vm?.onStatus) return;
      const unsub = vm.onStatus((update: VMStatusUpdate) => {
        if (update.sessionId !== session.id) return;

        setVmStatus(update.status);
        if (update.progress) {
          setVmProgress(update.progress);
        }
        if (update.event) {
          setEvents(prev => [...prev.slice(-999), update]);
        }
        if (update.error) {
          setLiveError(update.error);
        }
        if (update.status === 'completed') {
          // Fetch result
          fetchResult(update.instanceId);
        }
        if (update.status === 'error' || update.status === 'aborted') {
          setView('ready');
        }
      });
      return unsub;
    } catch {
      // vm namespace not available
    }
  }, [session.id]);

  // Check snapshot status when images load
  useEffect(() => {
    const vm = (window as any).shieldtier?.vm;
    if (!vm?.hasSnapshot) return;
    images.filter((i: any) => i.downloaded).forEach(async (img: any) => {
      try {
        const has = await vm.hasSnapshot(img.id);
        setSnapshotReady(prev => ({ ...prev, [img.id]: has }));
      } catch {}
    });
  }, [images]);

  // Listen for snapshot preparation progress
  useEffect(() => {
    try {
      const vm = (window as any).shieldtier?.vm;
      if (!vm?.onSnapshotProgress) return;
      const unsub = vm.onSnapshotProgress((data: { imageId: string; message: string }) => {
        setSnapshotMessage(data.message);
      });
      return unsub;
    } catch {}
  }, []);

  // Listen for image download progress
  useEffect(() => {
    try {
      const vm = (window as any).shieldtier?.vm;
      if (!vm?.onImageDownloadProgress) return;
      const unsub = vm.onImageDownloadProgress((progress: any) => {
        setDownloadProgress({
          percent: progress.percent || 0,
          downloadedMB: progress.downloadedMB || 0,
          totalMB: progress.totalMB || 0,
        });
        if (progress.percent >= 100 || progress.status === 'complete') {
          setDownloadingImageId(null);
          setDownloadProgress(null);
          // Refresh image list
          vm.listImages().then((imgs: any[]) => setImages(imgs)).catch(() => {});
        }
      });
      return unsub;
    } catch {}
  }, []);

  const handleDownloadImage = useCallback(async (imageId: string) => {
    const vm = (window as any).shieldtier?.vm;
    if (!vm?.downloadImage) return;
    setDownloadingImageId(imageId);
    setDownloadProgress({ percent: 0, downloadedMB: 0, totalMB: 0 });
    try {
      await vm.downloadImage(imageId);
      // Refresh images after download completes
      const imgs = await vm.listImages();
      setImages(imgs);
      // Auto-create snapshot for instant boot
      if (vm.prepareSnapshot) {
        setSnapshotMessage('Creating snapshot for fast boot...');
        try {
          await vm.prepareSnapshot(imageId);
          setSnapshotReady(prev => ({ ...prev, [imageId]: true }));
        } catch {
          // Non-fatal — snapshot can be created later on first run
        }
        setSnapshotMessage('');
      }
    } catch (err: any) {
      setLiveError(`Image download failed: ${err.message}`);
    } finally {
      setDownloadingImageId(null);
      setDownloadProgress(null);
    }
  }, []);

  // Auto-scroll event log
  useEffect(() => {
    if (eventLogRef.current) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
    }
  }, [events]);

  // Listen for live VM screenshots
  useEffect(() => {
    try {
      const vm = (window as any).shieldtier?.vm;
      if (!vm?.onScreenshot) return;
      const unsub = vm.onScreenshot((data: { instanceId: string; sessionId: string; screenshot: { timestamp: number; data: string } }) => {
        if (data.sessionId === session.id) {
          setLatestScreenshot(data.screenshot.data);
        }
      });
      return unsub;
    } catch {}
  }, [session.id]);

  // Render PPM screenshot to canvas when updated
  useEffect(() => {
    if (!latestScreenshot || !vmCanvasRef.current) return;
    renderPPMToCanvas(vmCanvasRef.current, latestScreenshot);
  }, [latestScreenshot]);

  const checkSetup = useCallback(async () => {
    const vm = (window as any).shieldtier?.vm;
    if (!vm) {
      setView('setup');
      return;
    }
    try {
      const status = await vm.getQEMUStatus();
      if (status.installed) {
        const imgs = await vm.listImages();
        setImages(imgs);
        const anyDownloaded = imgs.some((i: any) => i.downloaded);
        if (anyDownloaded) {
          setQemuReady(true);
          setView('ready');
        } else {
          setView('setup');
        }
      } else {
        setView('setup');
      }
    } catch {
      setView('setup');
    }
  }, []);

  const fetchResult = useCallback(async (instanceId: string) => {
    try {
      const r = await (window as any).shieldtier?.vm?.getResult(session.id, instanceId);
      if (r) {
        setResult(r);
        setView('results');
      }
    } catch {}
  }, [session.id]);

  const handleRunInVM = useCallback(async () => {
    if (!selectedFileId) return;
    const fa = (window as any).shieldtier?.fileanalysis;
    if (!fa?.analyzeInVM) return;

    setView('active');
    setEvents([]);
    setLiveError(null);
    setVmProgress('');
    setLatestScreenshot(null);
    setResult(null);

    try {
      // Route through FileAnalysisManager so it creates a pending SandboxResult
      // and transfers the file buffer to VMManager
      const instanceId = await fa.analyzeInVM(
        session.id,
        selectedFileId,
        {
          os: selectedOS,
          imageId: selectedImageId,
          timeoutSeconds: timeout,
          enableINetSim: true,
          enableScreenshots: true,
        }
      );
      if (!instanceId) {
        setLiveError('Failed to start VM analysis — file buffer may be unavailable');
        setView('ready');
        return;
      }
      setVmInstanceId(instanceId);
    } catch (err: any) {
      setLiveError(err.message);
      setView('ready');
    }
  }, [session.id, selectedFileId, selectedOS, selectedImageId, timeout]);

  const handleAbort = useCallback(async () => {
    if (vmInstanceId) {
      try {
        await (window as any).shieldtier?.vm?.killVM(vmInstanceId);
      } catch {}
    }
    setView('ready');
  }, [vmInstanceId]);

  // Get files list for picker
  const fileList = Array.from(files.values()).filter(
    (f: any) => f.status === 'complete' && f.hashes
  );

  // ═══════════════════════════════════════════════════════
  // Setup View
  // ═══════════════════════════════════════════════════════

  if (view === 'checking') {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-2 border-purple-500/30 border-t-purple-500 rounded-full" />
      </div>
    );
  }

  if (view === 'setup') {
    return <VMSetupWizard onComplete={() => { setQemuReady(true); checkSetup(); }} />;
  }

  // ═══════════════════════════════════════════════════════
  // Ready View — Configuration
  // ═══════════════════════════════════════════════════════

  if (view === 'ready') {
    return (
      <div className="h-full flex flex-col">
        {/* Header */}
        <div className="px-4 py-3 border-b glass-heavy flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-purple-400" strokeWidth="1.5">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-medium text-[color:var(--st-text-primary)]">VM Dynamic Analysis</h2>
              <p className="text-[11px] text-[color:var(--st-text-muted)]">Execute samples in isolated QEMU VMs</p>
            </div>
          </div>
          {result && (
            <button
              onClick={() => setView('results')}
              className="px-3 py-1.5 rounded-md glass-light border text-xs text-purple-400 hover:text-purple-300"
            >
              View Last Result
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-md mx-auto space-y-6">
            {liveError && (
              <div className="glass-light border border-red-500/30 rounded-lg p-3">
                <p className="text-xs text-red-400">{liveError}</p>
              </div>
            )}

            {/* File Selection */}
            <div>
              <label className="block text-xs text-[color:var(--st-text-secondary)] mb-1.5">Sample File</label>
              {fileList.length === 0 ? (
                <div className="glass-light border rounded-lg p-4 text-center">
                  <p className="text-sm text-[color:var(--st-text-muted)]">No captured files available</p>
                  <p className="text-[11px] text-[color:var(--st-text-muted)] mt-1">Download a file in the browser to analyze it in a VM</p>
                </div>
              ) : (
                <select
                  value={selectedFileId}
                  onChange={(e) => setSelectedFileId(e.target.value)}
                  className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border-subtle)] rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-purple-500/50"
                >
                  <option value="">Select a file...</option>
                  {fileList.map((f: any) => (
                    <option key={f.id} value={f.id}>
                      {f.originalName} ({(f.fileSize / 1024).toFixed(0)} KB) — {f.riskLevel}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* OS & Image Selection */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[color:var(--st-text-secondary)] mb-1.5">Guest OS</label>
                <div className="flex gap-2">
                  <button
                    onClick={() => { setSelectedOS('linux'); setSelectedImageId('alpine-3.19'); }}
                    className={`flex-1 py-2 rounded-lg text-xs font-medium border transition-colors ${
                      selectedOS === 'linux'
                        ? 'bg-orange-500/20 border-orange-500/50 text-orange-400'
                        : 'glass-light border-[color:var(--st-border-subtle)] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]'
                    }`}
                  >
                    Linux
                  </button>
                  <button
                    onClick={() => { setSelectedOS('windows'); setSelectedImageId('reactos-0.4.15'); }}
                    className={`flex-1 py-2 rounded-lg text-xs font-medium border transition-colors ${
                      selectedOS === 'windows'
                        ? 'bg-blue-500/20 border-blue-500/50 text-blue-400'
                        : 'glass-light border-[color:var(--st-border-subtle)] text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]'
                    }`}
                  >
                    Windows
                  </button>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs text-[color:var(--st-text-secondary)]">Image</label>
                  <button
                    onClick={() => setShowImageManager(!showImageManager)}
                    className="text-[10px] text-purple-400 hover:text-purple-300 transition-colors"
                  >
                    {showImageManager ? 'Hide' : 'Download Images'}
                  </button>
                </div>
                <select
                  value={selectedImageId}
                  onChange={(e) => setSelectedImageId(e.target.value)}
                  className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border-subtle)] rounded-lg px-3 py-2 text-sm text-[color:var(--st-text-primary)] focus:outline-none focus:border-purple-500/50"
                >
                  {images.filter((i: any) => i.os === selectedOS && i.downloaded).map((i: any) => (
                    <option key={i.id} value={i.id}>{i.name}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Image Download Manager */}
            {showImageManager && (
              <div className="glass-light border border-purple-500/20 rounded-lg p-3 space-y-2">
                <h4 className="text-xs font-medium text-purple-400">Available VM Images</h4>
                {snapshotMessage && (
                  <p className="text-[10px] text-cyan-400 animate-pulse">{snapshotMessage}</p>
                )}
                {images.map((img: any) => (
                  <div key={img.id} className="flex items-center justify-between py-1.5 border-b border-[color:var(--st-border-subtle)] last:border-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        img.os === 'linux' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'
                      }`}>
                        {img.os === 'linux' ? 'LNX' : 'WIN'}
                      </span>
                      <div className="min-w-0">
                        <p className="text-xs text-[color:var(--st-text-primary)] truncate">{img.name}</p>
                        <p className="text-[10px] text-[color:var(--st-text-muted)]">{img.sizeMB ? `${img.sizeMB} MB` : 'Size unknown'}</p>
                      </div>
                    </div>
                    <div className="shrink-0 ml-2">
                      {img.downloaded ? (
                        <span className="text-[10px] text-green-400 bg-green-500/20 px-2 py-0.5 rounded">
                          {snapshotReady[img.id] ? 'Ready' : 'Installed'}
                        </span>
                      ) : downloadingImageId === img.id ? (
                        <div className="flex items-center gap-2" aria-live="polite">
                          <div className="w-20 h-1.5 bg-[color:var(--st-accent-dim)] rounded-full overflow-hidden">
                            <div
                              className="h-full bg-purple-500 rounded-full transition-all duration-300"
                              style={{ width: `${downloadProgress?.percent || 0}%` }}
                            />
                          </div>
                          <span className="text-[10px] text-[color:var(--st-text-secondary)] w-8 text-right">{Math.round(downloadProgress?.percent || 0)}%</span>
                          {downloadProgress && downloadProgress.totalMB > 0 && (
                            <span className="text-[9px] text-[color:var(--st-text-muted)] shrink-0">{downloadProgress.downloadedMB.toFixed(0)}/{downloadProgress.totalMB.toFixed(0)} MB</span>
                          )}
                        </div>
                      ) : (
                        <button
                          onClick={() => handleDownloadImage(img.id)}
                          disabled={downloadingImageId !== null}
                          className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/30 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 transition-colors"
                        >
                          Download
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Timeout Slider */}
            <div>
              <label className="block text-xs text-[color:var(--st-text-secondary)] mb-1.5">
                Execution Timeout: <span className="text-[color:var(--st-text-primary)]">{timeout}s</span>
              </label>
              <input
                type="range"
                min={30}
                max={300}
                step={10}
                value={timeout}
                onChange={(e) => setTimeoutSec(parseInt(e.target.value))}
                className="w-full accent-purple-500"
              />
              <div className="flex justify-between text-[10px] text-[color:var(--st-text-muted)]">
                <span>30s</span>
                <span>300s</span>
              </div>
            </div>

            {/* Network Safety Notice */}
            <div className="glass-light border border-green-500/20 rounded-lg p-3 flex items-start gap-2">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-green-400 mt-0.5 shrink-0" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <div className="text-[11px] text-[color:var(--st-text-secondary)]">
                <span className="text-green-400 font-medium">Network Isolated</span> —
                VM traffic is fully contained via QEMU restrict=on. All DNS/HTTP/HTTPS
                goes to INetSim fake servers with TLS interception. Zero real internet access.
              </div>
            </div>

            {/* Run Button */}
            <button
              onClick={handleRunInVM}
              disabled={!selectedFileId || !images.some((i: any) => i.id === selectedImageId && i.downloaded)}
              className="w-full py-3 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-[color:var(--st-bg-elevated)] disabled:text-[color:var(--st-text-muted)] text-white text-sm font-medium transition-colors flex items-center justify-center gap-2"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="5 3 19 12 5 21 5 3"/>
              </svg>
              Execute in VM Sandbox
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════
  // Active View — Live Execution
  // ═══════════════════════════════════════════════════════

  if (view === 'active') {
    return (
      <div className="h-full flex flex-col">
        {/* Status Bar */}
        <div className="px-3 py-2 border-b glass-heavy flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="animate-spin w-4 h-4 border-2 border-red-500/30 border-t-red-500 rounded-full" />
            <div aria-live="polite">
              <p className="text-xs text-[color:var(--st-text-primary)] font-medium">
                {vmStatus === 'preparing' && 'Preparing VM...'}
                {vmStatus === 'booting' && 'Booting VM...'}
                {vmStatus === 'injecting' && 'Injecting sample...'}
                {vmStatus === 'executing' && 'Executing — monitoring behaviors...'}
                {vmStatus === 'collecting' && 'Collecting results...'}
              </p>
              {vmProgress && (
                <p className="text-[10px] text-cyan-400 font-mono">{vmProgress}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-[color:var(--st-text-muted)]">{events.length} events</span>
            <button
              onClick={handleAbort}
              className="px-3 py-1 rounded-md bg-red-600/80 hover:bg-red-500 text-white text-[11px] font-medium transition-colors"
            >
              Abort
            </button>
          </div>
        </div>

        {/* Error Banner */}
        {liveError && (
          <div className="px-3 py-1.5 bg-red-500/10 border-b border-red-500/30">
            <p className="text-[11px] text-red-400">{liveError}</p>
          </div>
        )}

        {/* Live VM Display */}
        <div className="flex-[3] min-h-0 bg-black flex items-center justify-center border-b border-[color:var(--st-border)]">
          {latestScreenshot ? (
            <canvas
              ref={vmCanvasRef}
              className="max-w-full max-h-full object-contain"
              style={{ imageRendering: 'auto' }}
            />
          ) : (
            <div className="flex flex-col items-center gap-2 text-[color:var(--st-text-muted)]">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="opacity-40">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
              <span className="text-[11px]">Waiting for VM display...</span>
            </div>
          )}
        </div>

        {/* Event Stream (compact) */}
        <div ref={eventLogRef} className="flex-[2] min-h-0 overflow-y-auto px-3 py-2 font-mono text-[10px] space-y-px">
          {events.map((ev, i) => (
            <div key={i} className="flex gap-1.5">
              <span className="text-[color:var(--st-text-muted)] shrink-0">
                {new Date(ev.event?.timestamp || Date.now()).toLocaleTimeString()}
              </span>
              <span className={getEventColor(ev.event?.type || ev.status)}>
                [{ev.event?.type || ev.status}]
              </span>
              <span className="text-[color:var(--st-text-secondary)] truncate">
                {formatEventData(ev.event?.data || {}, ev.event?.type || '')}
              </span>
            </div>
          ))}
          {events.length === 0 && (
            <div className="text-[color:var(--st-text-muted)] text-center mt-4">Waiting for events...</div>
          )}
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════
  // Results View — 6-Tab Report
  // ═══════════════════════════════════════════════════════

  if (view === 'results' && result) {
    const RESULT_TABS: { id: ResultTab; label: string; count?: number }[] = [
      { id: 'summary', label: 'Summary' },
      { id: 'processes', label: 'Processes', count: result.processCount },
      { id: 'behaviors', label: 'Behaviors', count: result.findings.length },
      { id: 'network', label: 'Network', count: result.networkSummary.totalConnections },
      { id: 'files', label: 'Files', count: result.fileOperations.length },
      { id: 'registry', label: 'Registry', count: result.registryOperations.length },
    ];

    return (
      <div className="h-full flex flex-col">
        {/* Header */}
        <div className="px-4 py-3 border-b glass-heavy flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`px-2.5 py-1 rounded-md text-xs font-bold border ${VERDICT_COLORS[result.verdict] || VERDICT_COLORS.unknown}`}>
              {result.verdict.toUpperCase()}
            </div>
            <div>
              <p className="text-sm text-[color:var(--st-text-primary)]">Score: {result.score}/100</p>
              <p className="text-[11px] text-[color:var(--st-text-muted)]">{(result.executionDurationMs / 1000).toFixed(1)}s execution</p>
            </div>
          </div>
          <button
            onClick={() => setView('ready')}
            className="px-3 py-1.5 rounded-md glass-light border text-xs text-[color:var(--st-text-secondary)] hover:text-[color:var(--st-text-primary)]"
          >
            New Analysis
          </button>
        </div>

        {/* Tab Bar */}
        <div className="px-4 py-1 border-b glass-heavy flex gap-1 overflow-x-auto">
          {RESULT_TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveResultTab(tab.id)}
              className={`px-3 py-1.5 rounded-t-md text-xs transition-colors whitespace-nowrap ${
                activeResultTab === tab.id
                  ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-primary)] border-b-2 border-purple-500'
                  : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="ml-1 text-[10px] text-[color:var(--st-text-muted)]">({tab.count})</span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {activeResultTab === 'summary' && <SummaryTab result={result} />}
          {activeResultTab === 'processes' && <ProcessesTab result={result} />}
          {activeResultTab === 'behaviors' && <BehaviorsTab result={result} />}
          {activeResultTab === 'network' && <NetworkTab result={result} />}
          {activeResultTab === 'files' && <FilesTab result={result} />}
          {activeResultTab === 'registry' && <RegistryTab result={result} />}
        </div>
      </div>
    );
  }

  return null;
}

// ═══════════════════════════════════════════════════════
// Result Tab Components
// ═══════════════════════════════════════════════════════

function SummaryTab({ result }: { result: VMAnalysisResult }) {
  return (
    <div className="space-y-4 max-w-2xl">
      {/* Score Gauge */}
      <div className="glass-light border rounded-lg p-4 flex items-center gap-6">
        <div className="relative w-20 h-20">
          <svg viewBox="0 0 36 36" className="w-full h-full">
            <path
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              fill="none"
              stroke="var(--st-border-subtle)"
              strokeWidth="3"
            />
            <path
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              fill="none"
              stroke={result.score >= 70 ? '#ef4444' : result.score >= 30 ? '#eab308' : '#22c55e'}
              strokeWidth="3"
              strokeDasharray={`${result.score}, 100`}
              strokeLinecap="round"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-bold text-[color:var(--st-text-primary)]">{result.score}</span>
          </div>
        </div>
        <div>
          <p className={`text-lg font-bold ${
            result.verdict === 'malicious' ? 'text-red-400' :
            result.verdict === 'suspicious' ? 'text-yellow-400' :
            'text-green-400'
          }`}>
            {result.verdict.charAt(0).toUpperCase() + result.verdict.slice(1)}
          </p>
          <div className="text-xs text-[color:var(--st-text-secondary)] mt-1 space-y-0.5">
            <p>{result.processCount} processes | {result.fileOperations.length} file ops | {result.networkSummary.totalConnections} connections</p>
            <p>{result.findings.length} findings | {result.mitreTechniques.length} MITRE techniques</p>
          </div>
        </div>
      </div>

      {/* MITRE Techniques */}
      {result.mitreTechniques.length > 0 && (
        <div className="glass-light border rounded-lg p-4">
          <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">MITRE ATT&CK Techniques</h3>
          <div className="flex flex-wrap gap-1.5">
            {result.mitreTechniques.map(t => (
              <span key={t} className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 text-[11px] font-mono">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Key Findings */}
      {result.findings.length > 0 && (
        <div className="glass-light border rounded-lg p-4">
          <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">Key Findings</h3>
          <div className="space-y-1.5">
            {result.findings.map((f, i) => (
              <div key={i} className="flex items-start gap-2 text-[11px]">
                <span className={`shrink-0 mt-0.5 w-1.5 h-1.5 rounded-full ${
                  f.severity === 'critical' ? 'bg-red-500' :
                  f.severity === 'high' ? 'bg-orange-500' :
                  f.severity === 'medium' ? 'bg-yellow-500' :
                  'bg-blue-500'
                }`} />
                <span className="text-[color:var(--st-text-secondary)]">{f.description}</span>
                {f.mitre && <span className="text-purple-500 shrink-0">{f.mitre}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Network Summary */}
      <div className="glass-light border rounded-lg p-4">
        <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">Network Summary</h3>
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-lg font-bold text-[color:var(--st-text-primary)]">{result.networkSummary.uniqueHosts.length}</p>
            <p className="text-[11px] text-[color:var(--st-text-muted)]">Unique Hosts</p>
          </div>
          <div>
            <p className="text-lg font-bold text-[color:var(--st-text-primary)]">{result.networkSummary.httpRequests}</p>
            <p className="text-[11px] text-[color:var(--st-text-muted)]">HTTP Requests</p>
          </div>
          <div>
            <p className="text-lg font-bold text-[color:var(--st-text-primary)]">{result.networkSummary.dnsQueries.length}</p>
            <p className="text-[11px] text-[color:var(--st-text-muted)]">DNS Queries</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ProcessesTab({ result }: { result: VMAnalysisResult }) {
  const renderTree = (nodes: any[], depth = 0): React.ReactNode[] => {
    return nodes.map((node, i) => (
      <div key={`${node.pid}-${i}`}>
        <div className="flex items-center gap-2 py-1 hover:bg-[color:var(--st-accent-dim)] rounded px-2" style={{ paddingLeft: `${depth * 16 + 8}px` }}>
          <span className="text-[11px] text-[color:var(--st-text-muted)] font-mono w-12">{node.pid}</span>
          <span className="text-[11px] text-[color:var(--st-text-primary)]">{node.name}</span>
          <span className="text-[11px] text-[color:var(--st-text-muted)] truncate flex-1">{node.commandLine}</span>
          {node.injectedBy && (
            <span className="text-[10px] text-red-400 bg-red-500/20 px-1.5 rounded">INJECTED</span>
          )}
        </div>
        {node.children && renderTree(node.children, depth + 1)}
      </div>
    ));
  };

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-[color:var(--st-text-primary)]">Process Tree ({result.processCount} total)</h3>
      <div className="glass-light border rounded-lg p-2 font-mono">
        {result.processTree.length > 0 ? (
          renderTree(result.processTree)
        ) : (
          <p className="text-xs text-[color:var(--st-text-muted)] text-center py-4">No processes recorded</p>
        )}
      </div>
    </div>
  );
}

function BehaviorsTab({ result }: { result: VMAnalysisResult }) {
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...result.findings].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-[color:var(--st-text-primary)]">Behavioral Findings ({result.findings.length})</h3>
      <div className="space-y-1">
        {sorted.map((f, i) => (
          <div key={i} className="glass-light border rounded-lg p-3 flex items-start gap-3">
            <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
              f.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
              f.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
              f.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-blue-500/20 text-blue-400'
            }`}>
              {f.severity}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-[color:var(--st-text-primary)]">{f.description}</p>
              <div className="flex gap-2 mt-1">
                <span className="text-[10px] text-[color:var(--st-text-muted)]">{f.category}</span>
                {f.mitre && <span className="text-[10px] text-purple-500">{f.mitre}</span>}
              </div>
            </div>
          </div>
        ))}
        {sorted.length === 0 && (
          <p className="text-xs text-[color:var(--st-text-muted)] text-center py-8">No behavioral findings</p>
        )}
      </div>
    </div>
  );
}

function NetworkTab({ result }: { result: VMAnalysisResult }) {
  return (
    <div className="space-y-4">
      {/* DNS Queries */}
      {result.networkSummary.dnsQueries.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">DNS Queries</h3>
          <div className="glass-light border rounded-lg overflow-hidden">
            <table className="w-full text-[11px]">
              <thead className="bg-[color:var(--st-accent-dim)]">
                <tr>
                  <th className="text-left px-3 py-1.5 text-[color:var(--st-text-muted)] font-medium">Hostname</th>
                  <th className="text-left px-3 py-1.5 text-[color:var(--st-text-muted)] font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {result.networkSummary.dnsQueries.map((q, i) => (
                  <tr key={i} className="border-t border-[color:var(--st-border-subtle)]">
                    <td className="px-3 py-1.5 text-[color:var(--st-text-primary)] font-mono">{q.hostname}</td>
                    <td className="px-3 py-1.5 text-[color:var(--st-text-secondary)] font-mono">{q.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* HTTP Connections */}
      {result.networkConnections.filter(c => c.httpUrl).length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">HTTP Requests</h3>
          <div className="space-y-1">
            {result.networkConnections.filter(c => c.httpUrl).map((c, i) => (
              <div key={i} className="glass-light border rounded-lg p-2 flex items-center gap-2 text-[11px]">
                <span className="text-purple-400 font-mono shrink-0">{c.httpMethod || 'GET'}</span>
                <span className="text-[color:var(--st-text-primary)] truncate">{c.httpUrl}</span>
                <span className="text-[color:var(--st-text-muted)] shrink-0">{c.httpStatus}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Unique Hosts */}
      {result.networkSummary.uniqueHosts.length > 0 && (
        <div>
          <h3 className="text-xs font-medium text-[color:var(--st-text-primary)] mb-2">Contacted Hosts ({result.networkSummary.uniqueHosts.length})</h3>
          <div className="flex flex-wrap gap-1.5">
            {result.networkSummary.uniqueHosts.map(h => (
              <span key={h} className="px-2 py-0.5 rounded bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-secondary)] text-[11px] font-mono">{h}</span>
            ))}
          </div>
        </div>
      )}

      {result.networkSummary.totalConnections === 0 && (
        <p className="text-xs text-[color:var(--st-text-muted)] text-center py-8">No network activity recorded</p>
      )}
    </div>
  );
}

function FilesTab({ result }: { result: VMAnalysisResult }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-[color:var(--st-text-primary)]">File Operations ({result.fileOperations.length})</h3>
      <div className="space-y-1">
        {result.fileOperations.map((f, i) => (
          <div key={i} className="glass-light border rounded-lg p-2 flex items-center gap-2 text-[11px]">
            <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold ${
              f.operation === 'create' ? 'bg-green-500/20 text-green-400' :
              f.operation === 'modify' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-red-500/20 text-red-400'
            }`}>
              {f.operation.toUpperCase()}
            </span>
            <span className="text-[color:var(--st-text-primary)] truncate flex-1 font-mono">{f.path}</span>
            {f.isExecutable && <span className="text-red-400 text-[10px]">EXE</span>}
            {f.isTemp && <span className="text-yellow-400 text-[10px]">TEMP</span>}
            {f.size && <span className="text-[color:var(--st-text-muted)] shrink-0">{(f.size / 1024).toFixed(0)} KB</span>}
          </div>
        ))}
        {result.fileOperations.length === 0 && (
          <p className="text-xs text-[color:var(--st-text-muted)] text-center py-8">No file operations recorded</p>
        )}
      </div>
    </div>
  );
}

function RegistryTab({ result }: { result: VMAnalysisResult }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-[color:var(--st-text-primary)]">Registry Operations ({result.registryOperations.length})</h3>
      <div className="space-y-1">
        {result.registryOperations.map((r, i) => (
          <div key={i} className="glass-light border rounded-lg p-2 text-[11px]">
            <div className="flex items-center gap-2">
              <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold ${
                r.operation === 'write' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'
              }`}>
                {r.operation.toUpperCase()}
              </span>
              {r.isPersistence && (
                <span className="text-red-400 text-[10px] bg-red-500/20 px-1.5 rounded">PERSISTENCE</span>
              )}
            </div>
            <p className="text-[color:var(--st-text-primary)] font-mono mt-1 truncate">{r.key}</p>
            {r.valueName && (
              <p className="text-[color:var(--st-text-muted)] font-mono truncate">{r.valueName} = {r.valueData || '(empty)'}</p>
            )}
          </div>
        ))}
        {result.registryOperations.length === 0 && (
          <p className="text-xs text-[color:var(--st-text-muted)] text-center py-8">No registry operations recorded</p>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════

function getEventColor(type: string): string {
  if (type.includes('process')) return 'text-blue-400';
  if (type.includes('file')) return 'text-green-400';
  if (type.includes('registry')) return 'text-yellow-400';
  if (type.includes('network') || type.includes('dns')) return 'text-purple-400';
  if (type.includes('memory') || type.includes('injection')) return 'text-red-400';
  if (type === 'error') return 'text-red-500';
  return 'text-[color:var(--st-text-muted)]';
}

function formatEventData(data: Record<string, any>, type: string): string {
  if (type === 'process_create') return `PID ${data.pid}: ${data.name} ${data.commandLine || ''}`;
  if (type === 'file_create' || type === 'file_modify' || type === 'file_delete') return data.path || '';
  if (type === 'registry_write') return `${data.key}\\${data.valueName || ''}`;
  if (type === 'network_connect') return `${data.remoteHost}:${data.remotePort}`;
  if (type === 'network_http') return `${data.method} ${data.url}`;
  if (type === 'network_dns') return `${data.hostname} → ${data.ip}`;
  if (type === 'memory_alloc') return `${data.address} (${data.size} bytes, ${data.protection})`;
  if (type === 'injection_detected') return `PID ${data.sourcePid} → PID ${data.targetPid}`;
  if (type === 'agent_ready') return 'Agent connected';
  if (type === 'execution_complete') return 'Execution finished';
  return JSON.stringify(data).slice(0, 100);
}
