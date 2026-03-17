import { useEffect, useRef } from 'react';

/**
 * Hides the BrowserView when an overlay (modal, dropdown, popover) mounts,
 * restores it when unmounted. The BrowserView is a native Electron overlay
 * that sits on top of all renderer HTML — any overlapping UI is hidden behind it.
 *
 * Uses the view.setBounds / hideView IPC pattern. When a session ID is
 * available, hides that session's view. Works with any Radix overlay.
 *
 * @param isOpen - Whether the overlay is currently visible
 * @param sessionId - Optional session ID whose BrowserView to hide
 */
export function useBrowserViewOverlay(isOpen: boolean, sessionId?: string | null) {
  const wasHiddenRef = useRef(false);

  useEffect(() => {
    if (!isOpen || !sessionId) return;

    window.shieldtier.view.hideView(sessionId);
    wasHiddenRef.current = true;

    return () => {
      // Don't restore — the Workspace layout effect handles restoring
      // bounds when modals close. We just need to trigger a hide.
      wasHiddenRef.current = false;
    };
  }, [isOpen, sessionId]);
}
