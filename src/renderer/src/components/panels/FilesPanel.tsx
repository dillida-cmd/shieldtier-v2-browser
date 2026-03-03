export function FilesPanel() {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-6 px-2 gap-2 border-b border-[var(--st-border)] flex-shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--st-text-muted)]">Files</span>
      </div>
      <div className="flex items-center justify-center h-full text-[var(--st-text-muted)] text-[10px]">No files captured</div>
    </div>
  );
}
