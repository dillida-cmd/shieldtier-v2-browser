import type { ThemeMode, FontSize } from '../../store';

interface Props {
  theme: ThemeMode;
  fontSize: FontSize;
  onThemeChange: (t: ThemeMode) => void;
  onFontSizeChange: (s: FontSize) => void;
}

const THEMES: { value: ThemeMode; label: string }[] = [
  { value: 'dark', label: 'Dark' },
  { value: 'light', label: 'Light' },
];

const FONT_SIZES: { value: FontSize; label: string }[] = [
  { value: 'sm', label: 'S' },
  { value: 'md', label: 'M' },
  { value: 'lg', label: 'L' },
];

export function AppearanceSection({ theme, fontSize, onThemeChange, onFontSizeChange }: Props) {
  return (
    <div className="flex flex-col gap-5">
      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-2 block">
          Theme
        </label>
        <div className="flex gap-2">
          {THEMES.map((t) => (
            <button
              key={t.value}
              onClick={() => onThemeChange(t.value)}
              className="px-4 py-2 rounded text-[11px] font-bold transition-colors"
              style={{
                background: theme === t.value ? 'var(--st-accent)' : 'var(--st-glass-input-bg)',
                color: theme === t.value ? 'var(--st-bg-primary)' : 'var(--st-text-label)',
                border: `1px solid ${theme === t.value ? 'var(--st-accent)' : 'var(--st-border)'}`,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="text-[10px] uppercase tracking-wider text-[var(--st-text-muted)] font-bold mb-2 block">
          Font Size
        </label>
        <div className="flex gap-2">
          {FONT_SIZES.map((s) => (
            <button
              key={s.value}
              onClick={() => onFontSizeChange(s.value)}
              className="w-10 h-10 rounded text-[12px] font-bold transition-colors"
              style={{
                background: fontSize === s.value ? 'var(--st-accent)' : 'var(--st-glass-input-bg)',
                color: fontSize === s.value ? 'var(--st-bg-primary)' : 'var(--st-text-label)',
                border: `1px solid ${fontSize === s.value ? 'var(--st-accent)' : 'var(--st-border)'}`,
              }}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
