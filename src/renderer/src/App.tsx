import { WorkspaceRoot } from './components/workspace/WorkspaceRoot';
import { TooltipProvider } from './components/ui/Tooltip';
import { useAnalysisPolling } from './hooks/useAnalysis';
import { useCapturePolling } from './hooks/useCapture';
import { useThreatLevel } from './hooks/useThreatLevel';

export function App() {
  useAnalysisPolling();
  useCapturePolling();
  useThreatLevel();

  return (
    <TooltipProvider delayDuration={300}>
      <WorkspaceRoot />
    </TooltipProvider>
  );
}
