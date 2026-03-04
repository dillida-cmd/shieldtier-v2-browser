import { useEffect } from 'react';
import { useStore } from '../store';
import type { BottomTab } from '../store';

const INDEX_TO_TAB: Record<string, BottomTab> = {
  '1': 'network',
  '2': 'ioc',
  '3': 'screenshots',
  '4': 'files',
  '5': 'sandbox',
  '6': 'findings',
  '7': 'mitre',
  '8': 'activity',
  '9': 'timeline',
  '0': 'process',
};

export function useKeyboardShortcuts() {
  const setModalState = useStore((s) => s.setModalState);
  const setBottomPrimaryTab = useStore((s) => s.setBottomPrimaryTab);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const mod = e.metaKey || e.ctrlKey;

      if (e.key === 'Escape') {
        e.preventDefault();
        setModalState('none');
        return;
      }

      if (!mod) return;

      if (e.key === 'k') {
        e.preventDefault();
        const current = useStore.getState().modalState;
        setModalState(current === 'command' ? 'none' : 'command');
        return;
      }

      if (e.key === 'n') {
        e.preventDefault();
        setModalState('caseName');
        return;
      }

      if (e.key === ',') {
        e.preventDefault();
        setModalState('settings');
        return;
      }

      if (e.key === 'e') {
        e.preventDefault();
        setModalState('export');
        return;
      }

      const tab = INDEX_TO_TAB[e.key];
      if (tab) {
        e.preventDefault();
        setBottomPrimaryTab(tab);
        return;
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [setModalState, setBottomPrimaryTab]);
}
