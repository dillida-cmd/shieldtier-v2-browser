// ---------------------------------------------------------------------------
// ShieldTier Log Analysis — Empty Section Placeholder
// ---------------------------------------------------------------------------

import React from 'react';

export function EmptySection({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center h-48 text-[color:var(--st-text-muted)] text-xs">
      {message}
    </div>
  );
}
