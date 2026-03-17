import React, { useState, useRef, useCallback } from 'react';

interface ChatMessageInputProps {
  onSend: (body: string) => void;
  disabled?: boolean;
}

export default function ChatMessageInput({ onSend, disabled }: ChatMessageInputProps) {
  const [text, setText] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSend = useCallback(() => {
    const trimmed = text.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setText('');
    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  }, [text, disabled, onSend]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  const handleInput = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setText(e.target.value);
    // Auto-resize
    const ta = e.target;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  }, []);

  return (
    <div style={{
      display: 'flex',
      alignItems: 'flex-end',
      gap: 8,
      padding: '8px 12px',
      borderTop: '1px solid var(--st-border-subtle)',
      backgroundColor: 'var(--st-accent-dim)',
    }}>
      <textarea
        ref={textareaRef}
        value={text}
        onChange={handleInput}
        onKeyDown={handleKeyDown}
        placeholder="Type a message..."
        disabled={disabled}
        rows={1}
        style={{
          flex: 1,
          resize: 'none',
          background: 'var(--st-accent-dim)',
          border: '1px solid var(--st-glass-border)',
          borderRadius: 8,
          padding: '8px 12px',
          color: 'var(--st-text-primary)',
          fontSize: 13,
          fontFamily: 'inherit',
          outline: 'none',
          maxHeight: 120,
          lineHeight: '1.4',
        }}
      />
      <button
        onClick={handleSend}
        disabled={disabled || !text.trim()}
        style={{
          padding: '8px 16px',
          borderRadius: 8,
          border: 'none',
          background: text.trim() ? '#3b82f6' : 'var(--st-border-subtle)',
          color: text.trim() ? '#fff' : 'var(--st-text-muted)',
          fontSize: 13,
          fontWeight: 600,
          cursor: text.trim() ? 'pointer' : 'default',
          transition: 'all 0.15s',
          whiteSpace: 'nowrap',
        }}
      >
        Send
      </button>
    </div>
  );
}
