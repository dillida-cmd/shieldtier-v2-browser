import React, { useState, useEffect, useCallback } from 'react';

// ═══════════════════════════════════════════════════════
// Types (mirrored from main process)
// ═══════════════════════════════════════════════════════

interface YARAStringDef {
  id: string;
  type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers: { nocase?: boolean; wide?: boolean; ascii?: boolean; fullword?: boolean };
}

interface YARARule {
  id: string;
  name: string;
  tags: string[];
  metadata: Record<string, string | number | boolean>;
  strings: YARAStringDef[];
  condition: string;
  enabled: boolean;
  source: 'custom' | 'builtin';
  pack?: string;
}

interface YARAMatchedString {
  stringId: string;
  offset: number;
  length: number;
  data: string;
}

interface YARAMatch {
  ruleId: string;
  ruleName: string;
  tags: string[];
  metadata: Record<string, string | number | boolean>;
  matchedStrings: YARAMatchedString[];
}

interface YARAScanResult {
  targetId: string;
  targetName: string;
  targetType: 'file' | 'content';
  matches: YARAMatch[];
  rulesScanned: number;
  scanTimeMs: number;
  timestamp: number;
}

interface YARARulePack {
  id: string;
  name: string;
  description: string;
  ruleCount: number;
  enabled: boolean;
}

// ═══════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════

interface YARAPanelProps {
  session: { id: string };
}

export function YARAPanel({ session }: YARAPanelProps) {
  const [subTab, setSubTab] = useState<'rules' | 'results'>('rules');
  const [rules, setRules] = useState<YARARule[]>([]);
  const [results, setResults] = useState<YARAScanResult[]>([]);
  const [packs, setPacks] = useState<YARARulePack[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedResultIdx, setSelectedResultIdx] = useState<number | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [autoScan, setAutoScan] = useState(true);
  const [scanning, setScanning] = useState(false);

  // Editor state
  const [editName, setEditName] = useState('');
  const [editTags, setEditTags] = useState('');
  const [editStrings, setEditStrings] = useState<YARAStringDef[]>([]);
  const [editCondition, setEditCondition] = useState('');
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    const [r, res, p] = await Promise.all([
      window.shieldtier.yara.getRules(),
      window.shieldtier.yara.getScanResults(session.id),
      window.shieldtier.yara.getBuiltinPacks(),
    ]);
    setRules(r);
    setResults(res);
    setPacks(p);
  }, [session.id]);

  useEffect(() => { loadData(); }, [loadData]);

  // Listen for scan results
  useEffect(() => {
    const unsub = window.shieldtier.yara.onScanResult((_sessionId: string, result: YARAScanResult) => {
      if (_sessionId === session.id) {
        setResults(prev => [...prev, result]);
      }
    });
    return () => { unsub(); };
  }, [session.id]);

  const handleTogglePack = async (packId: string, enabled: boolean) => {
    await window.shieldtier.yara.togglePack(packId, enabled);
    const p = await window.shieldtier.yara.getBuiltinPacks();
    setPacks(p);
    const r = await window.shieldtier.yara.getRules();
    setRules(r);
  };

  const handleScanAllFiles = async () => {
    setScanning(true);
    try {
      const files = await window.shieldtier.fileanalysis.getFiles(session.id);
      for (const file of files) {
        if (file.quarantinePath && file.status === 'complete') {
          await window.shieldtier.yara.scanFile(session.id, file.id, file.quarantinePath, file.originalName);
        }
      }
    } finally {
      setScanning(false);
      const res = await window.shieldtier.yara.getScanResults(session.id);
      setResults(res);
    }
  };

  const handleAddRule = () => {
    setEditingRuleId(null);
    setEditName('');
    setEditTags('');
    setEditStrings([{ id: '$s1', type: 'text', value: '', modifiers: {} }]);
    setEditCondition('any of them');
    setShowEditor(true);
  };

  const handleEditRule = (rule: YARARule) => {
    setEditingRuleId(rule.id);
    setEditName(rule.name);
    setEditTags(rule.tags.join(' '));
    setEditStrings([...rule.strings]);
    setEditCondition(rule.condition);
    setShowEditor(true);
  };

  const handleDeleteRule = async (ruleId: string) => {
    await window.shieldtier.yara.deleteRule(ruleId);
    setSelectedRuleId(null);
    loadData();
  };

  const handleSaveRule = async () => {
    const ruleData = {
      name: editName,
      tags: editTags.trim().split(/\s+/).filter(Boolean),
      metadata: {} as Record<string, string | number | boolean>,
      strings: editStrings,
      condition: editCondition,
      enabled: true,
      pack: undefined as string | undefined,
    };

    if (editingRuleId) {
      await window.shieldtier.yara.updateRule(editingRuleId, ruleData);
    } else {
      await window.shieldtier.yara.addRule(ruleData);
    }

    setShowEditor(false);
    loadData();
  };

  const handleImportYar = async () => {
    const text = await navigator.clipboard.readText();
    if (text && text.includes('rule ')) {
      await window.shieldtier.yara.importRules(text);
      loadData();
    }
  };

  const handleToggleAutoScan = async () => {
    const next = !autoScan;
    setAutoScan(next);
    // Stored via config
  };

  const addStringDef = () => {
    const nextNum = editStrings.length + 1;
    setEditStrings(prev => [...prev, { id: `$s${nextNum}`, type: 'text', value: '', modifiers: {} }]);
  };

  const updateStringDef = (idx: number, field: string, value: any) => {
    setEditStrings(prev => {
      const next = [...prev];
      (next[idx] as any)[field] = value;
      return next;
    });
  };

  const removeStringDef = (idx: number) => {
    setEditStrings(prev => prev.filter((_, i) => i !== idx));
  };

  const selectedRule = selectedRuleId ? rules.find(r => r.id === selectedRuleId) : null;
  const selectedResult = selectedResultIdx !== null ? results[selectedResultIdx] : null;
  const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);

  // Group rules by pack/source
  const groupedRules: Record<string, YARARule[]> = {};
  for (const rule of rules) {
    const group = rule.pack || (rule.source === 'custom' ? 'Custom' : 'Other');
    if (!groupedRules[group]) groupedRules[group] = [];
    groupedRules[group].push(rule);
  }

  return (
    <div className="flex flex-col h-full bg-[color:var(--st-bg-base)] text-[color:var(--st-text-primary)] text-xs">
      {/* Sub-tabs */}
      <div className="flex items-center gap-1 px-3 py-1.5 border-b border-[color:var(--st-border)]">
        <button
          onClick={() => setSubTab('rules')}
          aria-label="Rules tab"
          className={`px-2.5 py-1 rounded focus-visible:ring-2 focus-visible:ring-purple-500/60 focus-visible:outline-none ${subTab === 'rules' ? 'bg-purple-600/20 text-purple-400 border border-purple-500/30' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]'}`}
        >
          Rules ({rules.length})
        </button>
        <button
          onClick={() => setSubTab('results')}
          aria-label="Results tab"
          className={`px-2.5 py-1 rounded focus-visible:ring-2 focus-visible:ring-purple-500/60 focus-visible:outline-none ${subTab === 'results' ? 'bg-purple-600/20 text-purple-400 border border-purple-500/30' : 'text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]'}`}
        >
          Results ({totalMatches})
        </button>
        <div className="flex-1" />
        {subTab === 'rules' && (
          <>
            <button onClick={handleAddRule} className="px-2 py-0.5 bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 rounded border border-purple-500/30 focus-visible:ring-2 focus-visible:ring-purple-500/60 focus-visible:outline-none">
              + Add Rule
            </button>
            <button onClick={handleImportYar} className="px-2 py-0.5 bg-[color:var(--st-bg-elevated)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-accent-dim)] rounded border border-[color:var(--st-border-subtle)] focus-visible:ring-2 focus-visible:ring-purple-500/60 focus-visible:outline-none" title="Import YARA rules from clipboard">
              Import .yar
            </button>
          </>
        )}
        {subTab === 'results' && (
          <button
            onClick={handleScanAllFiles}
            disabled={scanning}
            className={`px-2 py-0.5 rounded border focus-visible:ring-2 focus-visible:ring-purple-500/60 focus-visible:outline-none ${scanning ? 'bg-[color:var(--st-bg-elevated)] text-[color:var(--st-text-muted)] border-[color:var(--st-border-subtle)]' : 'bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 border-purple-500/30'}`}
          >
            {scanning ? 'Scanning...' : 'Scan All Files'}
          </button>
        )}
        <label className="flex items-center gap-1 text-[color:var(--st-text-muted)] ml-2 cursor-pointer">
          <input type="checkbox" checked={autoScan} onChange={handleToggleAutoScan} className="accent-purple-500" />
          Auto-scan
        </label>
      </div>

      {/* Pack toggle chips */}
      {subTab === 'rules' && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-[color:var(--st-border)]">
          <span className="text-[color:var(--st-text-muted)] text-[10px]">Packs:</span>
          {packs.map(pack => (
            <button
              key={pack.id}
              onClick={() => handleTogglePack(pack.id, !pack.enabled)}
              className={`px-2 py-0.5 rounded-full text-[10px] border transition-colors ${
                pack.enabled
                  ? 'bg-purple-600/20 text-purple-400 border-purple-500/30'
                  : 'bg-[color:var(--st-bg-elevated)] text-[color:var(--st-text-muted)] border-[color:var(--st-border-subtle)]'
              }`}
              title={pack.description}
            >
              {pack.name} ({pack.ruleCount})
            </button>
          ))}
        </div>
      )}

      {/* Split view */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left list */}
        <div className="w-72 border-r border-[color:var(--st-border)] overflow-y-auto">
          {subTab === 'rules' ? (
            Object.entries(groupedRules).map(([group, groupRules]) => (
              <div key={group}>
                <div className="px-3 py-1 bg-[color:var(--st-bg-panel)] text-[color:var(--st-text-muted)] text-[10px] uppercase tracking-wider sticky top-0">
                  {group} ({groupRules.length})
                </div>
                {groupRules.map(rule => (
                  <div
                    key={rule.id}
                    onClick={() => setSelectedRuleId(rule.id)}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedRuleId(rule.id); } }}
                    tabIndex={0}
                    role="button"
                    className={`px-3 py-1.5 cursor-pointer border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-bg-elevated)] focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-purple-500/60 focus-visible:outline-none ${
                      selectedRuleId === rule.id ? 'bg-[color:var(--st-bg-elevated)] border-l-2 border-l-purple-500' : ''
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-[color:var(--st-text-muted)]'}`} />
                      <span className="text-[color:var(--st-text-primary)] truncate flex-1">{rule.name}</span>
                      <span className={`text-[9px] px-1 rounded ${rule.source === 'builtin' ? 'bg-blue-600/20 text-blue-400' : 'bg-green-600/20 text-green-400'}`}>
                        {rule.source}
                      </span>
                    </div>
                    {rule.tags.length > 0 && (
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {rule.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="text-[9px] text-[color:var(--st-text-muted)]">{tag}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ))
          ) : (
            results.map((result, idx) => (
              <div
                key={idx}
                onClick={() => setSelectedResultIdx(idx)}
                className={`px-3 py-1.5 cursor-pointer border-b border-[color:var(--st-border)] hover:bg-[color:var(--st-bg-elevated)] ${
                  selectedResultIdx === idx ? 'bg-[color:var(--st-bg-elevated)] border-l-2 border-l-purple-500' : ''
                }`}
              >
                <div className="flex items-center gap-1.5">
                  <span className={`text-[9px] px-1 rounded ${result.targetType === 'file' ? 'bg-orange-600/20 text-orange-400' : 'bg-cyan-600/20 text-cyan-400'}`}>
                    {result.targetType}
                  </span>
                  <span className="text-[color:var(--st-text-primary)] truncate flex-1">{result.targetName}</span>
                  {result.matches.length > 0 && (
                    <span className="text-[9px] bg-red-600/20 text-red-400 px-1.5 rounded-full">
                      {result.matches.length}
                    </span>
                  )}
                </div>
                <div className="text-[color:var(--st-text-muted)] text-[10px] mt-0.5">
                  {result.rulesScanned} rules · {result.scanTimeMs}ms · {new Date(result.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right detail */}
        <div className="flex-1 overflow-y-auto p-4">
          {showEditor ? (
            /* Rule Editor */
            <div className="space-y-3">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm text-purple-400">{editingRuleId ? 'Edit Rule' : 'New Rule'}</h3>
                <div className="flex gap-2">
                  <button onClick={() => setShowEditor(false)} className="px-2 py-0.5 text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-primary)]">Cancel</button>
                  <button onClick={handleSaveRule} className="px-3 py-0.5 bg-purple-600/30 text-purple-400 hover:bg-purple-600/40 rounded border border-purple-500/30">Save</button>
                </div>
              </div>

              <div>
                <label className="text-[color:var(--st-text-muted)] text-[10px]">Rule Name</label>
                <input
                  value={editName}
                  onChange={e => setEditName(e.target.value)}
                  className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-2 py-1 text-[color:var(--st-text-primary)] text-xs focus:border-purple-500/50 outline-none"
                  placeholder="My_Custom_Rule"
                />
              </div>

              <div>
                <label className="text-[color:var(--st-text-muted)] text-[10px]">Tags (space-separated)</label>
                <input
                  value={editTags}
                  onChange={e => setEditTags(e.target.value)}
                  className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-2 py-1 text-[color:var(--st-text-primary)] text-xs focus:border-purple-500/50 outline-none"
                  placeholder="malware dropper"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[color:var(--st-text-muted)] text-[10px]">Strings</label>
                  <button onClick={addStringDef} className="text-[10px] text-purple-400 hover:text-purple-300">+ Add String</button>
                </div>
                {editStrings.map((s, idx) => (
                  <div key={idx} className="flex gap-1 mb-1 items-center">
                    <input
                      value={s.id}
                      onChange={e => updateStringDef(idx, 'id', e.target.value)}
                      className="w-16 bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-1 py-0.5 text-[color:var(--st-text-muted)] text-[10px]"
                    />
                    <select
                      value={s.type}
                      onChange={e => updateStringDef(idx, 'type', e.target.value)}
                      className="bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-1 py-0.5 text-[color:var(--st-text-muted)] text-[10px]"
                    >
                      <option value="text">text</option>
                      <option value="hex">hex</option>
                      <option value="regex">regex</option>
                    </select>
                    <input
                      value={s.value}
                      onChange={e => updateStringDef(idx, 'value', e.target.value)}
                      className="flex-1 bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-1 py-0.5 text-[color:var(--st-text-primary)] text-[10px] font-mono"
                      placeholder={s.type === 'hex' ? 'AB CD ?? EF' : s.type === 'regex' ? 'pattern' : 'search text'}
                    />
                    <label className="flex items-center gap-0.5 text-[9px] text-[color:var(--st-text-muted)]">
                      <input type="checkbox" checked={!!s.modifiers.nocase} onChange={e => updateStringDef(idx, 'modifiers', { ...s.modifiers, nocase: e.target.checked })} />nc
                    </label>
                    <button onClick={() => removeStringDef(idx)} className="text-red-500 hover:text-red-400 text-[10px]">x</button>
                  </div>
                ))}
              </div>

              <div>
                <label className="text-[color:var(--st-text-muted)] text-[10px]">Condition</label>
                <input
                  value={editCondition}
                  onChange={e => setEditCondition(e.target.value)}
                  className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded px-2 py-1 text-[color:var(--st-text-primary)] text-xs font-mono focus:border-purple-500/50 outline-none"
                  placeholder="any of them"
                />
              </div>
            </div>
          ) : subTab === 'rules' && selectedRule ? (
            /* Rule Detail */
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm text-purple-400">{selectedRule.name}</h3>
                {selectedRule.source === 'custom' && (
                  <div className="flex gap-2">
                    <button onClick={() => handleEditRule(selectedRule)} className="px-2 py-0.5 text-[color:var(--st-text-muted)] hover:text-blue-400 text-[10px]">Edit</button>
                    <button onClick={() => handleDeleteRule(selectedRule.id)} className="px-2 py-0.5 text-[color:var(--st-text-muted)] hover:text-red-400 text-[10px]">Delete</button>
                  </div>
                )}
              </div>

              {selectedRule.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {selectedRule.tags.map(tag => (
                    <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-purple-600/10 text-purple-400 rounded">{tag}</span>
                  ))}
                </div>
              )}

              {Object.keys(selectedRule.metadata).length > 0 && (
                <div>
                  <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Metadata</h4>
                  <table className="w-full text-[10px]">
                    <tbody>
                      {Object.entries(selectedRule.metadata).map(([k, v]) => (
                        <tr key={k} className="border-b border-[color:var(--st-border)]">
                          <td className="text-[color:var(--st-text-muted)] pr-3 py-0.5">{k}</td>
                          <td className="text-[color:var(--st-text-secondary)] py-0.5">{String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {selectedRule.strings.length > 0 && (
                <div>
                  <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Strings ({selectedRule.strings.length})</h4>
                  {selectedRule.strings.map(s => (
                    <div key={s.id} className="flex items-center gap-2 py-0.5 font-mono text-[10px]">
                      <span className="text-[color:var(--st-text-muted)] w-12">{s.id}</span>
                      <span className={`px-1 rounded text-[9px] ${
                        s.type === 'text' ? 'bg-green-600/20 text-green-400' :
                        s.type === 'hex' ? 'bg-orange-600/20 text-orange-400' :
                        'bg-cyan-600/20 text-cyan-400'
                      }`}>{s.type}</span>
                      <span className="text-[color:var(--st-text-secondary)] flex-1 truncate">
                        {s.type === 'text' ? `"${s.value}"` : s.type === 'hex' ? `{ ${s.value} }` : `/${s.value}/`}
                      </span>
                      {Object.entries(s.modifiers).filter(([, v]) => v).map(([k]) => (
                        <span key={k} className="text-[9px] text-yellow-500">{k}</span>
                      ))}
                    </div>
                  ))}
                </div>
              )}

              <div>
                <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Condition</h4>
                <div className="font-mono text-[11px] text-[color:var(--st-text-secondary)] bg-[color:var(--st-bg-panel)] rounded px-2 py-1 border border-[color:var(--st-border)]">
                  {selectedRule.condition}
                </div>
              </div>
            </div>
          ) : subTab === 'results' && selectedResult ? (
            /* Result Detail */
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${selectedResult.targetType === 'file' ? 'bg-orange-600/20 text-orange-400' : 'bg-cyan-600/20 text-cyan-400'}`}>
                  {selectedResult.targetType}
                </span>
                <h3 className="text-sm text-[color:var(--st-text-primary)]">{selectedResult.targetName}</h3>
              </div>

              <div className="flex gap-4 text-[10px] text-[color:var(--st-text-muted)]">
                <span>{selectedResult.rulesScanned} rules scanned</span>
                <span>{selectedResult.scanTimeMs}ms</span>
                <span>{new Date(selectedResult.timestamp).toLocaleString()}</span>
              </div>

              {selectedResult.matches.length === 0 ? (
                <div className="text-[color:var(--st-text-muted)] text-sm py-8 text-center">No matches found</div>
              ) : (
                selectedResult.matches.map((match, mIdx) => (
                  <div key={mIdx} className="bg-[color:var(--st-bg-panel)] rounded border border-[color:var(--st-border)] p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-red-400 font-medium">{match.ruleName}</span>
                      {match.tags.map(tag => (
                        <span key={tag} className="text-[9px] px-1 bg-red-600/10 text-red-400 rounded">{tag}</span>
                      ))}
                    </div>

                    {match.metadata.description && (
                      <div className="text-[color:var(--st-text-muted)] text-[10px]">{String(match.metadata.description)}</div>
                    )}

                    {match.matchedStrings.length > 0 && (
                      <div>
                        <h4 className="text-[color:var(--st-text-muted)] text-[10px] mb-1">Matched Strings ({match.matchedStrings.length})</h4>
                        <div className="max-h-64 overflow-y-auto">
                          {match.matchedStrings.map((ms, msIdx) => (
                            <div key={msIdx} className="flex items-center gap-2 py-0.5 font-mono text-[10px]">
                              <span className="text-[color:var(--st-text-muted)] w-12">{ms.stringId}</span>
                              <span className="text-[color:var(--st-text-muted)] w-20">@{ms.offset}</span>
                              <span className="text-orange-400 truncate flex-1" title={ms.data}>
                                {ms.data.length > 64 ? ms.data.slice(0, 64) + '...' : ms.data}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-[color:var(--st-text-muted)] text-sm">
              {subTab === 'rules' ? 'Select a rule to view details' : 'Select a scan result to view details'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
