/**
 * DESIGN REFERENCE ONLY — Do not import into the app.
 * Template: Network HAR Capture Table
 * Target: src/renderer/src/components/panels/NetworkPanel.tsx
 * Source: 21st.dev Magic MCP Builder
 *
 * Key design patterns to extract:
 * - Toolbar: capture toggle (Play/Pause), view mode switcher (grouped/flat), export, search
 * - Domain-grouped collapsible rows with threat badges + whitelist toggles
 * - Per-entry: status (color-coded), method, URL (mono), MIME, size, timing
 * - Expandable detail: Headers/Cookies/Response tabs
 * - Filter panel (method, status, threat level) with animated sidebar
 * - Sticky column headers
 */

"use client";

import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import {
  Play,
  Pause,
  Download,
  Filter,
  Search,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Shield,
  Clock,
  Globe,
  X,
  Check,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface HAREntry {
  id: string;
  domain: string;
  timestamp: string;
  status: number;
  method: string;
  url: string;
  mimeType: string;
  size: number;
  time: number;
  threatLevel: "none" | "low" | "medium" | "high";
  headers: Record<string, string>;
  cookies: Array<{ name: string; value: string; domain: string }>;
  response: string;
}

interface DomainGroup {
  domain: string;
  entries: HAREntry[];
  whitelisted: boolean;
  threatLevel: "none" | "low" | "medium" | "high";
}

type ViewMode = "grouped" | "flat";

const SAMPLE_ENTRIES: HAREntry[] = [
  {
    id: "1",
    domain: "api.example.com",
    timestamp: "2024-01-15T10:23:45.123Z",
    status: 200,
    method: "GET",
    url: "https://api.example.com/v1/users",
    mimeType: "application/json",
    size: 2048,
    time: 245,
    threatLevel: "none",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJhbGc...",
      "User-Agent": "Mozilla/5.0",
    },
    cookies: [
      { name: "session_id", value: "abc123", domain: ".example.com" },
    ],
    response: '{"users": [{"id": 1, "name": "John Doe"}]}',
  },
  {
    id: "2",
    domain: "cdn.malicious.net",
    timestamp: "2024-01-15T10:23:46.456Z",
    status: 403,
    method: "POST",
    url: "https://cdn.malicious.net/track.js",
    mimeType: "application/javascript",
    size: 15360,
    time: 1200,
    threatLevel: "high",
    headers: {
      "Content-Type": "application/javascript",
      "X-Tracking": "enabled",
    },
    cookies: [],
    response: "// Suspicious tracking code",
  },
  {
    id: "3",
    domain: "api.example.com",
    timestamp: "2024-01-15T10:23:47.789Z",
    status: 201,
    method: "POST",
    url: "https://api.example.com/v1/posts",
    mimeType: "application/json",
    size: 512,
    time: 189,
    threatLevel: "none",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJhbGc...",
    },
    cookies: [
      { name: "session_id", value: "abc123", domain: ".example.com" },
    ],
    response: '{"id": 42, "created": true}',
  },
  {
    id: "4",
    domain: "analytics.suspicious.io",
    timestamp: "2024-01-15T10:23:48.012Z",
    status: 200,
    method: "GET",
    url: "https://analytics.suspicious.io/pixel.gif?user=12345",
    mimeType: "image/gif",
    size: 43,
    time: 567,
    threatLevel: "medium",
    headers: {
      "Content-Type": "image/gif",
      "X-Fingerprint": "enabled",
    },
    cookies: [
      { name: "tracking_id", value: "xyz789", domain: ".suspicious.io" },
    ],
    response: "GIF89a...",
  },
  {
    id: "5",
    domain: "static.example.com",
    timestamp: "2024-01-15T10:23:49.345Z",
    status: 304,
    method: "GET",
    url: "https://static.example.com/assets/style.css",
    mimeType: "text/css",
    size: 0,
    time: 12,
    threatLevel: "none",
    headers: {
      "Content-Type": "text/css",
      "Cache-Control": "max-age=31536000",
    },
    cookies: [],
    response: "",
  },
  {
    id: "6",
    domain: "cdn.malicious.net",
    timestamp: "2024-01-15T10:23:50.678Z",
    status: 500,
    method: "GET",
    url: "https://cdn.malicious.net/exploit.wasm",
    mimeType: "application/wasm",
    size: 98304,
    time: 3400,
    threatLevel: "high",
    headers: {
      "Content-Type": "application/wasm",
    },
    cookies: [],
    response: "Binary data...",
  },
];

const statusColors: Record<number, string> = {
  200: "text-[#00ff41]",
  201: "text-[#00ff41]",
  204: "text-[#00ff41]",
  304: "text-[#00d9ff]",
  400: "text-[#ffff00]",
  401: "text-[#ffff00]",
  403: "text-[#ff6b00]",
  404: "text-[#ff6b00]",
  500: "text-[#ff0055]",
  502: "text-[#ff0055]",
  503: "text-[#ff0055]",
};

const threatColors = {
  none: "bg-[#00ff41]/20 text-[#00ff41] border-[#00ff41]/40 shadow-[0_0_10px_rgba(0,255,65,0.3)]",
  low: "bg-[#ffff00]/20 text-[#ffff00] border-[#ffff00]/40 shadow-[0_0_10px_rgba(255,255,0,0.3)]",
  medium: "bg-[#ff6b00]/20 text-[#ff6b00] border-[#ff6b00]/40 shadow-[0_0_10px_rgba(255,107,0,0.3)]",
  high: "bg-[#ff0055]/20 text-[#ff0055] border-[#ff0055]/40 shadow-[0_0_10px_rgba(255,0,85,0.3)]",
};

function EntryRow({
  entry,
  expanded,
  onToggle,
}: {
  entry: HAREntry;
  expanded: boolean;
  onToggle: () => void;
}) {
  const statusColor = statusColors[entry.status] || "text-muted-foreground";

  return (
    <>
      <motion.button
        onClick={onToggle}
        className="w-full px-3 py-2 text-left transition-colors hover:bg-[#2a2a2c] active:bg-[#323234] border-b border-[#2a2a2c]"
      >
        <div className="flex items-center gap-3 text-xs">
          <motion.div
            animate={{ rotate: expanded ? 90 : 0 }}
            transition={{ duration: 0.2 }}
            className="flex-shrink-0"
          >
            <ChevronRight className="h-3 w-3 text-gray-500" />
          </motion.div>

          {entry.threatLevel !== "none" && (
            <AlertTriangle
              className={cn(
                "h-3 w-3 flex-shrink-0",
                entry.threatLevel === "high" && "text-[#ff0055] drop-shadow-[0_0_4px_rgba(255,0,85,0.8)]",
                entry.threatLevel === "medium" && "text-[#ff6b00] drop-shadow-[0_0_4px_rgba(255,107,0,0.8)]",
                entry.threatLevel === "low" && "text-[#ffff00] drop-shadow-[0_0_4px_rgba(255,255,0,0.8)]"
              )}
            />
          )}

          <span className={cn("w-12 flex-shrink-0 font-mono font-semibold", statusColor)}>
            {entry.status}
          </span>

          <span className="w-16 flex-shrink-0 font-mono text-gray-400">
            {entry.method}
          </span>

          <span className="flex-1 truncate font-mono text-gray-300">
            {entry.url}
          </span>

          <span className="w-32 flex-shrink-0 truncate text-gray-500">
            {entry.mimeType}
          </span>

          <span className="w-20 flex-shrink-0 text-right font-mono text-gray-400">
            {(entry.size / 1024).toFixed(1)} KB
          </span>

          <span className="w-16 flex-shrink-0 text-right font-mono text-gray-400">
            {entry.time}ms
          </span>
        </div>
      </motion.button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden bg-[#232325] border-b border-[#2a2a2c]"
          >
            <div className="p-4">
              <Tabs defaultValue="headers" className="w-full">
                <TabsList className="bg-[#1c1c1e] border border-[#2a2a2c]">
                  <TabsTrigger value="headers">Headers</TabsTrigger>
                  <TabsTrigger value="cookies">Cookies</TabsTrigger>
                  <TabsTrigger value="response">Response</TabsTrigger>
                </TabsList>
                <TabsContent value="headers" className="mt-3">
                  <div className="space-y-2">
                    {Object.entries(entry.headers).map(([key, value]) => (
                      <div key={key} className="flex gap-3 text-xs font-mono border-b border-[#2a2a2c] pb-2">
                        <span className="text-[#00d9ff] font-semibold w-40 flex-shrink-0">{key}:</span>
                        <span className="text-gray-300 break-all">{value}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>
                <TabsContent value="cookies" className="mt-3">
                  {entry.cookies.length > 0 ? (
                    <div className="space-y-2">
                      {entry.cookies.map((cookie, idx) => (
                        <div key={idx} className="p-2 bg-[#1c1c1e] rounded border border-[#2a2a2c]">
                          <div className="flex gap-2 text-xs font-mono">
                            <span className="text-[#ff00ff] font-semibold">{cookie.name}:</span>
                            <span className="text-gray-300">{cookie.value}</span>
                          </div>
                          <div className="text-xs text-gray-500 mt-1">Domain: {cookie.domain}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-500">No cookies</p>
                  )}
                </TabsContent>
                <TabsContent value="response" className="mt-3">
                  <pre className="p-3 bg-[#1c1c1e] rounded border border-[#2a2a2c] text-xs font-mono text-gray-300 overflow-x-auto">
                    {entry.response}
                  </pre>
                </TabsContent>
              </Tabs>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

function DomainGroupRow({
  group,
  expanded,
  onToggle,
  onWhitelistToggle,
  expandedEntryId,
  onEntryToggle,
}: {
  group: DomainGroup;
  expanded: boolean;
  onToggle: () => void;
  onWhitelistToggle: () => void;
  expandedEntryId: string | null;
  onEntryToggle: (id: string) => void;
}) {
  const maxThreatLevel = group.entries.reduce((max, entry) => {
    const levels = { none: 0, low: 1, medium: 2, high: 3 };
    return levels[entry.threatLevel] > levels[max] ? entry.threatLevel : max;
  }, "none" as "none" | "low" | "medium" | "high");

  return (
    <>
      <motion.div className="border-b border-[#2a2a2c] bg-[#232325]">
        <div className="flex items-center gap-3 px-3 py-3">
          <button onClick={onToggle} className="flex items-center gap-2 flex-1">
            <motion.div animate={{ rotate: expanded ? 90 : 0 }} transition={{ duration: 0.2 }}>
              <ChevronRight className="h-4 w-4 text-gray-400" />
            </motion.div>
            <Globe className="h-4 w-4 text-[#00d9ff]" />
            <span className="font-mono text-sm text-gray-200 font-semibold">{group.domain}</span>
            <Badge variant="outline" className={cn("text-xs border", threatColors[maxThreatLevel])}>
              {maxThreatLevel}
            </Badge>
            <span className="text-xs text-gray-500">({group.entries.length} requests)</span>
          </button>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">Whitelist</span>
            <Switch checked={group.whitelisted} onCheckedChange={onWhitelistToggle} className="scale-75" />
          </div>
        </div>
      </motion.div>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            {group.entries.map((entry) => (
              <EntryRow
                key={entry.id}
                entry={entry}
                expanded={expandedEntryId === entry.id}
                onToggle={() => onEntryToggle(entry.id)}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default function HARNetworkCaptureTable() {
  const [capturing, setCapturing] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>("grouped");
  const [searchQuery, setSearchQuery] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);
  const [whitelistedDomains, setWhitelistedDomains] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState({ method: [] as string[], status: [] as string[], threatLevel: [] as string[] });

  const filteredEntries = useMemo(() => {
    return SAMPLE_ENTRIES.filter((entry) => {
      const matchSearch = entry.url.toLowerCase().includes(searchQuery.toLowerCase()) || entry.domain.toLowerCase().includes(searchQuery.toLowerCase());
      const matchMethod = filters.method.length === 0 || filters.method.includes(entry.method);
      const matchStatus = filters.status.length === 0 || filters.status.includes(String(entry.status));
      const matchThreat = filters.threatLevel.length === 0 || filters.threatLevel.includes(entry.threatLevel);
      return matchSearch && matchMethod && matchStatus && matchThreat;
    });
  }, [searchQuery, filters]);

  const domainGroups = useMemo(() => {
    const groups = new Map<string, HAREntry[]>();
    filteredEntries.forEach((entry) => {
      if (!groups.has(entry.domain)) groups.set(entry.domain, []);
      groups.get(entry.domain)!.push(entry);
    });
    return Array.from(groups.entries()).map(([domain, entries]) => ({
      domain,
      entries,
      whitelisted: whitelistedDomains.has(domain),
      threatLevel: entries.reduce((max, entry) => {
        const levels = { none: 0, low: 1, medium: 2, high: 3 };
        return levels[entry.threatLevel] > levels[max] ? entry.threatLevel : max;
      }, "none" as "none" | "low" | "medium" | "high"),
    }));
  }, [filteredEntries, whitelistedDomains]);

  return (
    <div className="h-screen w-full bg-[#1c1c1e] text-gray-200 flex flex-col">
      {/* Toolbar */}
      <div className="border-b border-[#2a2a2c] bg-[#1c1c1e] p-4">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-semibold text-gray-100">Network Capture</h1>
              <p className="text-xs text-gray-500">{filteredEntries.length} of {SAMPLE_ENTRIES.length} requests</p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant={capturing ? "destructive" : "default"} size="sm" onClick={() => setCapturing(!capturing)} className="gap-2">
                {capturing ? <><Pause className="h-3 w-3" />Stop</> : <><Play className="h-3 w-3" />Capture</>}
              </Button>
              <Button variant="outline" size="sm" className="gap-2 border-[#2a2a2c] bg-[#232325]">
                <Download className="h-3 w-3" />Export
              </Button>
            </div>
          </div>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3 w-3 -translate-y-1/2 text-gray-500" />
              <Input placeholder="Search by URL or domain..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="h-8 pl-9 text-xs bg-[#232325] border-[#2a2a2c]" />
            </div>
            <div className="flex gap-1 border border-[#2a2a2c] rounded-md p-1 bg-[#232325]">
              <button onClick={() => setViewMode("grouped")} className={cn("px-3 py-1 text-xs rounded", viewMode === "grouped" ? "bg-[#00d9ff] text-black font-semibold" : "text-gray-400")}>Grouped</button>
              <button onClick={() => setViewMode("flat")} className={cn("px-3 py-1 text-xs rounded", viewMode === "flat" ? "bg-[#00d9ff] text-black font-semibold" : "text-gray-400")}>Flat</button>
            </div>
            <Button variant="outline" size="sm" onClick={() => setShowFilters(!showFilters)} className={cn("relative", showFilters ? "border-[#00d9ff] bg-[#00d9ff]/20 text-[#00d9ff]" : "border-[#2a2a2c] bg-[#232325] text-gray-500")}>
              <Filter className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 overflow-y-auto">
          {/* Sticky Column Headers */}
          <div className="sticky top-0 z-10 bg-[#232325] border-b border-[#2a2a2c] px-3 py-2">
            <div className="flex items-center gap-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
              <div className="w-3" />
              <div className="w-12">Status</div>
              <div className="w-16">Method</div>
              <div className="flex-1">URL</div>
              <div className="w-32">Type</div>
              <div className="w-20 text-right">Size</div>
              <div className="w-16 text-right"><Clock className="h-3 w-3 inline" /></div>
            </div>
          </div>

          <div>
            {viewMode === "grouped" ? (
              domainGroups.map((group) => (
                <DomainGroupRow
                  key={group.domain}
                  group={group}
                  expanded={expandedDomain === group.domain}
                  onToggle={() => setExpandedDomain(expandedDomain === group.domain ? null : group.domain)}
                  onWhitelistToggle={() => {
                    const newSet = new Set(whitelistedDomains);
                    if (newSet.has(group.domain)) newSet.delete(group.domain);
                    else newSet.add(group.domain);
                    setWhitelistedDomains(newSet);
                  }}
                  expandedEntryId={expandedEntryId}
                  onEntryToggle={(id) => setExpandedEntryId(expandedEntryId === id ? null : id)}
                />
              ))
            ) : (
              filteredEntries.map((entry) => (
                <EntryRow
                  key={entry.id}
                  entry={entry}
                  expanded={expandedEntryId === entry.id}
                  onToggle={() => setExpandedEntryId(expandedEntryId === entry.id ? null : entry.id)}
                />
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
