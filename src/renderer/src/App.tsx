import { WorkspaceRoot } from './components/workspace/WorkspaceRoot';
import { TooltipProvider } from './components/ui/Tooltip';
import { useAnalysisPolling } from './hooks/useAnalysis';
import { useCapturePolling } from './hooks/useCapture';
import { useThreatLevel } from './hooks/useThreatLevel';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { CommandPalette } from './components/CommandPalette';
import { CaseNameModal } from './components/modals/CaseNameModal';
import { SettingsModal } from './components/modals/SettingsModal';
import { ExportModal } from './components/modals/ExportModal';

export function App() {
  useAnalysisPolling();
  useCapturePolling();
  useThreatLevel();
  useKeyboardShortcuts();

  return (
    <TooltipProvider delayDuration={300}>
      <WorkspaceRoot />
      <CommandPalette />
      <CaseNameModal />
      <SettingsModal />
      <ExportModal />
    </TooltipProvider>
  );
}
