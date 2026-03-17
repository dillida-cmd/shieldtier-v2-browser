/**
 * VMSetupWizard — first-time QEMU + image setup flow.
 *
 * Steps:
 *   1. Check QEMU status → install if missing
 *   2. Show available images → download selected
 *   3. Ready confirmation
 */

import React, { useState, useEffect, useCallback } from 'react';

interface QEMUStatus {
  installed: boolean;
  path: string | null;
  version: string | null;
  accelerator: string;
  hwAccel: boolean;
}

interface ImageInfo {
  id: string;
  name: string;
  os: string;
  version: string;
  downloadSize: number;
  diskSize: number;
  downloaded: boolean;
}

interface VMSetupWizardProps {
  onComplete: () => void;
}

type WizardStep = 'checking' | 'install-qemu' | 'installing' | 'select-images' | 'downloading' | 'ready';

export default function VMSetupWizard({ onComplete }: VMSetupWizardProps) {
  const [step, setStep] = useState<WizardStep>('checking');
  const [qemuStatus, setQemuStatus] = useState<QEMUStatus | null>(null);
  const [images, setImages] = useState<ImageInfo[]>([]);
  const [installLog, setInstallLog] = useState<string[]>([]);
  const [downloadProgress, setDownloadProgress] = useState<{ imageId: string; percent: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Check QEMU on mount
  useEffect(() => {
    checkQEMU();
  }, []);

  const checkQEMU = useCallback(async () => {
    setStep('checking');
    setError(null);
    try {
      const status = await (window as any).shieldtier?.vm?.getQEMUStatus();
      setQemuStatus(status);
      if (status.installed) {
        await loadImages();
      } else {
        setStep('install-qemu');
      }
    } catch (err: any) {
      setError(err.message);
      setStep('install-qemu');
    }
  }, []);

  const loadImages = useCallback(async () => {
    try {
      const imgs = await (window as any).shieldtier?.vm?.listImages();
      setImages(imgs);
      const anyDownloaded = imgs.some((i: ImageInfo) => i.downloaded);
      if (anyDownloaded) {
        setStep('ready');
      } else {
        setStep('select-images');
      }
    } catch (err: any) {
      setError(err.message);
      setStep('select-images');
    }
  }, []);

  const handleInstallQEMU = useCallback(async () => {
    setStep('installing');
    setInstallLog([]);
    setError(null);
    try {
      // Listen for install progress
      const unsub = (window as any).shieldtier?.vm?.onInstallProgress((msg: string) => {
        setInstallLog(prev => [...prev, msg]);
      });

      await (window as any).shieldtier?.vm?.installQEMU();
      unsub();

      // Re-check status
      const status = await (window as any).shieldtier?.vm?.getQEMUStatus();
      setQemuStatus(status);
      if (status.installed) {
        await loadImages();
      } else {
        setError('QEMU installation failed. Please install manually.');
        setStep('install-qemu');
      }
    } catch (err: any) {
      setError(err.message);
      setStep('install-qemu');
    }
  }, [loadImages]);

  const handleDownloadImage = useCallback(async (imageId: string) => {
    setStep('downloading');
    setDownloadProgress({ imageId, percent: 0 });
    setError(null);
    try {
      const vm = (window as any).shieldtier?.vm;
      const unsub = vm?.onImageDownloadProgress(
        (progress: { imageId: string; percent: number }) => {
          setDownloadProgress(progress);
        }
      );

      await vm?.downloadImage(imageId);
      unsub();

      // Auto-create snapshot for instant boot
      if (vm?.prepareSnapshot) {
        setDownloadProgress({ imageId, percent: 100 });
        try {
          await vm.prepareSnapshot(imageId);
        } catch {
          // Non-fatal — snapshot can be created later on first run
        }
      }

      await loadImages();
    } catch (err: any) {
      setError(err.message);
      setStep('select-images');
    }
  }, [loadImages]);

  const formatSize = (bytes: number) => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    return `${Math.round(bytes / (1024 * 1024))} MB`;
  };

  return (
    <div className="h-full flex items-center justify-center p-8">
      <div className="max-w-lg w-full glass-heavy border rounded-2xl p-8 mx-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-purple-500/20 flex items-center justify-center">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-purple-400" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
              <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-[color:var(--st-text-primary)]">VM Sandbox Setup</h2>
          <p className="text-sm text-gray-400 mt-1">Execute malware in isolated virtual machines</p>
        </div>

        {/* Step: Checking */}
        {step === 'checking' && (
          <div className="text-center">
            <div className="animate-spin w-8 h-8 border-2 border-purple-500/30 border-t-purple-500 rounded-full mx-auto mb-4" />
            <p className="text-sm text-gray-400">Detecting QEMU installation...</p>
          </div>
        )}

        {/* Step: Install QEMU */}
        {step === 'install-qemu' && (
          <div className="space-y-4">
            <div className="glass-light border rounded-lg p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-red-400" strokeWidth="2">
                    <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-[color:var(--st-text-primary)]">QEMU Not Found</p>
                  <p className="text-xs text-gray-400">Required for VM-based analysis</p>
                </div>
              </div>
              <p className="text-xs text-gray-500">
                QEMU is a free, open-source machine emulator. ShieldTier uses it to
                execute malware samples in fully isolated virtual machines.
              </p>
            </div>

            {error && (
              <div className="glass-light border border-red-500/30 rounded-lg p-3">
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <button
              onClick={handleInstallQEMU}
              className="w-full py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-medium transition-colors"
            >
              Install QEMU Automatically
            </button>

            <p className="text-[11px] text-gray-600 text-center">
              Auto-detects your platform and installs QEMU
            </p>
          </div>
        )}

        {/* Step: Installing */}
        {step === 'installing' && (
          <div className="space-y-4" aria-live="polite">
            <div className="flex items-center gap-3 mb-2">
              <div className="animate-spin w-5 h-5 border-2 border-purple-500/30 border-t-purple-500 rounded-full" />
              <p className="text-sm text-[color:var(--st-text-primary)]">Installing QEMU...</p>
            </div>
            <div className="glass-light border rounded-lg p-3 max-h-40 overflow-y-auto font-mono text-[11px] text-gray-400 space-y-0.5">
              {installLog.map((line, i) => (
                <div key={i}>{line}</div>
              ))}
              {installLog.length === 0 && <div className="text-gray-600">Waiting for output...</div>}
            </div>
          </div>
        )}

        {/* Step: Select Images */}
        {step === 'select-images' && (
          <div className="space-y-4">
            {qemuStatus?.installed && (
              <div className="glass-light border border-green-500/30 rounded-lg p-3 flex items-center gap-3">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-green-400" strokeWidth="2">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <div>
                  <p className="text-xs text-[color:var(--st-text-primary)]">QEMU {qemuStatus.version} detected</p>
                  <p className="text-[11px] text-gray-500">
                    Accelerator: {qemuStatus.accelerator.toUpperCase()}
                    {qemuStatus.hwAccel ? ' (hardware)' : ' (software)'}
                  </p>
                </div>
              </div>
            )}

            <p className="text-sm text-gray-300">Download a VM image to get started:</p>

            {error && (
              <div className="glass-light border border-red-500/30 rounded-lg p-3">
                <p className="text-xs text-red-400">{error}</p>
              </div>
            )}

            <div className="space-y-2">
              {images.map(img => (
                <div key={img.id} className="glass-light border rounded-lg p-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      img.os === 'linux' ? 'bg-orange-500/20' : 'bg-blue-500/20'
                    }`}>
                      <span className="text-xs font-bold" style={{ color: img.os === 'linux' ? '#fb923c' : '#60a5fa' }}>
                        {img.os === 'linux' ? 'LX' : 'WN'}
                      </span>
                    </div>
                    <div>
                      <p className="text-sm text-[color:var(--st-text-primary)]">{img.name}</p>
                      <p className="text-[11px] text-gray-500">
                        Download: {formatSize(img.downloadSize)} | Disk: {formatSize(img.diskSize)}
                      </p>
                    </div>
                  </div>
                  {img.downloaded ? (
                    <span className="text-xs text-green-400 flex items-center gap-1">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12"/>
                      </svg>
                      Ready
                    </span>
                  ) : (
                    <button
                      onClick={() => handleDownloadImage(img.id)}
                      className="px-3 py-1.5 rounded-md bg-purple-600/80 hover:bg-purple-500 text-white text-xs font-medium transition-colors"
                    >
                      Download
                    </button>
                  )}
                </div>
              ))}
            </div>

            {images.some(i => i.downloaded) && (
              <button
                onClick={onComplete}
                className="w-full py-2.5 rounded-lg bg-green-600 hover:bg-green-500 text-white text-sm font-medium transition-colors"
              >
                Continue to VM Sandbox
              </button>
            )}
          </div>
        )}

        {/* Step: Downloading */}
        {step === 'downloading' && downloadProgress && (
          <div className="space-y-4" aria-live="polite">
            <p className="text-sm text-[color:var(--st-text-primary)]">
              Downloading {images.find(i => i.id === downloadProgress.imageId)?.name || downloadProgress.imageId}...
            </p>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-purple-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${downloadProgress.percent}%` }}
              />
            </div>
            <p className="text-xs text-gray-400 text-center">{downloadProgress.percent}%</p>
          </div>
        )}

        {/* Step: Ready */}
        {step === 'ready' && (
          <div className="space-y-4 text-center">
            <div className="w-12 h-12 mx-auto rounded-full bg-green-500/20 flex items-center justify-center">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" className="text-green-400" strokeWidth="2">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </div>
            <div>
              <p className="text-sm text-[color:var(--st-text-primary)] font-medium">VM Sandbox Ready</p>
              <p className="text-xs text-gray-400 mt-1">
                QEMU {qemuStatus?.version} with {qemuStatus?.accelerator.toUpperCase()} acceleration
              </p>
              <p className="text-xs text-gray-500 mt-0.5">
                {images.filter(i => i.downloaded).length} image{images.filter(i => i.downloaded).length !== 1 ? 's' : ''} available
              </p>
            </div>
            <button
              onClick={onComplete}
              className="w-full py-2.5 rounded-lg bg-green-600 hover:bg-green-500 text-white text-sm font-medium transition-colors"
            >
              Open VM Sandbox
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
