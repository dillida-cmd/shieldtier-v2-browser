/**
 * DESIGN REFERENCE ONLY — Do not import into the app.
 * Template: Mission Control Dashboard (Landing Page)
 * Target: src/renderer/src/components/dashboard/Dashboard.tsx
 * Source: 21st.dev Magic MCP Builder
 *
 * Key design patterns to extract:
 * - Greeting header + dual UTC/Local clock
 * - Quick action cards with hover glow radial gradient
 * - Session stats row with monospace tabular numbers
 * - Recent cases list with severity + status badges
 * - IOC lookup with verdict display + redirect chain visualization
 * - System health footer with status dots
 */

'use client'

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Shield, AlertTriangle, Activity, CheckCircle, XCircle, Globe, ExternalLink, Settings, FileSearch, Clock } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';

interface Case {
  id: string;
  title: string;
  status: 'active' | 'closed' | 'pending';
  severity: 'high' | 'medium' | 'low';
  timestamp: string;
  iocs: number;
}

interface IOCResult {
  indicator: string;
  type: string;
  verdict: 'malicious' | 'suspicious' | 'clean';
  confidence: number;
  redirectChain?: string[];
}

interface SessionStats {
  totalCases: number;
  activeCases: number;
  closedCases: number;
  activeTime: string;
}

const ForensicBrowserMissionControl = () => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [searchQuery, setSearchQuery] = useState('');
  const [iocQuery, setIocQuery] = useState('');
  const [iocResult, setIocResult] = useState<IOCResult | null>(null);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatUTC = (date: Date) => {
    return date.toUTCString().split(' ').slice(0, 5).join(' ');
  };

  const recentCases: Case[] = [
    { id: 'INV-2024-001', title: 'Phishing Campaign Analysis', status: 'active', severity: 'high', timestamp: '2024-01-15 14:32', iocs: 23 },
    { id: 'INV-2024-002', title: 'Malware Distribution Network', status: 'active', severity: 'high', timestamp: '2024-01-15 13:15', iocs: 45 },
    { id: 'INV-2024-003', title: 'Suspicious Domain Investigation', status: 'pending', severity: 'medium', timestamp: '2024-01-15 11:20', iocs: 12 },
    { id: 'INV-2024-004', title: 'C2 Infrastructure Mapping', status: 'closed', severity: 'high', timestamp: '2024-01-14 16:45', iocs: 67 },
    { id: 'INV-2024-005', title: 'Credential Harvesting Site', status: 'closed', severity: 'medium', timestamp: '2024-01-14 09:30', iocs: 8 },
  ];

  const sessionStats: SessionStats = {
    totalCases: 12,
    activeCases: 2,
    closedCases: 10,
    activeTime: '4h 23m'
  };

  const handleIOCLookup = () => {
    if (!iocQuery.trim()) return;

    const mockResult: IOCResult = {
      indicator: iocQuery,
      type: iocQuery.includes('.') ? 'domain' : 'hash',
      verdict: Math.random() > 0.5 ? 'malicious' : 'suspicious',
      confidence: Math.floor(Math.random() * 30) + 70,
      redirectChain: iocQuery.includes('.') ? [
        iocQuery,
        'cdn.malicious-site.com',
        'payload.evil-domain.net'
      ] : undefined
    };
    setIocResult(mockResult);
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'malicious': return 'text-red-500';
      case 'suspicious': return 'text-yellow-500';
      case 'clean': return 'text-green-500';
      default: return 'text-gray-400';
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'malicious': return <XCircle className="w-5 h-5" />;
      case 'suspicious': return <AlertTriangle className="w-5 h-5" />;
      case 'clean': return <CheckCircle className="w-5 h-5" />;
      default: return null;
    }
  };

  return (
    <div className="min-h-screen bg-black text-white p-6 font-sans">
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header with Greeting and UTC Clock */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between"
        >
          <div>
            <h1 className="text-3xl font-semibold mb-1" style={{ fontFamily: 'Inter, sans-serif' }}>
              Good Evening, Analyst
            </h1>
            <p className="text-gray-400 text-sm">Mission Control Dashboard</p>
          </div>
          <div className="flex items-center gap-3 bg-[#0a0a0a] rounded-2xl px-6 py-3 border border-[#1a1a1a]">
            <Clock className="w-5 h-5 text-[#e43f5a]" />
            <div className="text-right">
              <div className="text-xs text-gray-400 font-mono">UTC TIME</div>
              <div className="text-lg font-mono font-semibold">{formatUTC(currentTime)}</div>
            </div>
          </div>
        </motion.div>

        {/* Quick Action Cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-4"
        >
          {[
            { icon: FileSearch, title: 'New Investigation', desc: 'Start forensic analysis', color: '#e43f5a' },
            { icon: Globe, title: 'Investigate URL', desc: 'Analyze suspicious links', color: '#1f4068' },
            { icon: Settings, title: 'Settings', desc: 'Configure preferences', color: '#f39c12' }
          ].map((action, idx) => (
            <motion.div
              key={idx}
              whileHover={{ scale: 1.02, y: -2 }}
              className="relative bg-[#0a0a0a] rounded-2xl p-6 border border-[#1a1a1a] cursor-pointer overflow-hidden group"
              style={{
                boxShadow: '0 4px 20px rgba(10, 132, 255, 0.1)'
              }}
            >
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                style={{
                  background: `radial-gradient(circle at center, ${action.color}15 0%, transparent 70%)`,
                  filter: 'blur(20px)'
                }}
              />
              <div className="relative z-10">
                <div
                  className="w-12 h-12 rounded-xl flex items-center justify-center mb-4"
                  style={{
                    background: `${action.color}20`,
                    boxShadow: `0 0 20px ${action.color}40`
                  }}
                >
                  <action.icon className="w-6 h-6" style={{ color: action.color }} />
                </div>
                <h3 className="text-lg font-semibold mb-1">{action.title}</h3>
                <p className="text-sm text-gray-400">{action.desc}</p>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Session Stats Row */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4"
        >
          {[
            { label: 'Total Cases', value: sessionStats.totalCases, icon: FileSearch },
            { label: 'Active Cases', value: sessionStats.activeCases, icon: Shield },
            { label: 'Closed Cases', value: sessionStats.closedCases, icon: CheckCircle },
            { label: 'Active Time', value: sessionStats.activeTime, icon: Clock }
          ].map((stat, idx) => (
            <div
              key={idx}
              className="bg-[#0a0a0a] rounded-2xl p-5 border border-[#1a1a1a]"
            >
              <div className="flex items-center gap-2 mb-2">
                <stat.icon className="w-4 h-4 text-[#e43f5a]" />
                <span className="text-xs text-gray-400 uppercase tracking-wide">{stat.label}</span>
              </div>
              <div className="text-2xl font-bold font-mono">{stat.value}</div>
            </div>
          ))}
        </motion.div>

        {/* Two Column Layout: Recent Cases + IOC Lookup */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        >
          {/* Recent Cases */}
          <div className="bg-[#0a0a0a] rounded-2xl p-6 border border-[#1a1a1a]">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold">Recent Cases</h2>
              <Badge variant="secondary" className="bg-[#e43f5a]20 text-[#e43f5a] border-0">
                {recentCases.filter(c => c.status === 'active').length} Active
              </Badge>
            </div>
            <div className="space-y-3">
              {recentCases.map((caseItem) => (
                <motion.div
                  key={caseItem.id}
                  whileHover={{ x: 4 }}
                  className="bg-black rounded-xl p-4 border border-[#1a1a1a] cursor-pointer"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-gray-500">{caseItem.id}</span>
                        <Badge
                          variant="outline"
                          className={`text-xs border-0 ${
                            caseItem.severity === 'high'
                              ? 'bg-red-500/20 text-red-400'
                              : caseItem.severity === 'medium'
                              ? 'bg-yellow-500/20 text-yellow-400'
                              : 'bg-blue-500/20 text-blue-400'
                          }`}
                        >
                          {caseItem.severity}
                        </Badge>
                      </div>
                      <h3 className="text-sm font-medium mb-1">{caseItem.title}</h3>
                      <div className="flex items-center gap-3 text-xs text-gray-400">
                        <span>{caseItem.timestamp}</span>
                        <span>•</span>
                        <span>{caseItem.iocs} IOCs</span>
                      </div>
                    </div>
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        caseItem.status === 'active'
                          ? 'bg-green-500/20 text-green-400 border-green-500/30'
                          : caseItem.status === 'pending'
                          ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                          : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                      }`}
                    >
                      {caseItem.status}
                    </Badge>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          {/* IOC Lookup */}
          <div className="bg-[#0a0a0a] rounded-2xl p-6 border border-[#1a1a1a]">
            <h2 className="text-xl font-semibold mb-6">IOC Lookup</h2>
            <div className="space-y-4">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <Input
                    value={iocQuery}
                    onChange={(e) => setIocQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleIOCLookup()}
                    placeholder="Enter domain, IP, or hash..."
                    className="pl-10 bg-black border-[#1a1a1a] text-white placeholder:text-gray-500 rounded-xl font-mono text-sm"
                  />
                </div>
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={handleIOCLookup}
                  className="px-6 py-2 bg-gradient-to-r from-[#e43f5a] to-[#e74c3c] text-white rounded-xl font-medium text-sm"
                  style={{
                    boxShadow: '0 0 20px rgba(228, 63, 90, 0.5)'
                  }}
                >
                  Analyze
                </motion.button>
              </div>

              {iocResult && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-black rounded-xl p-5 border border-[#1a1a1a] space-y-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="text-xs text-gray-400 uppercase tracking-wide mb-1">Indicator</div>
                      <div className="font-mono text-sm break-all">{iocResult.indicator}</div>
                    </div>
                    <Badge variant="outline" className="bg-[#e43f5a]20 text-[#e43f5a] border-0 text-xs">
                      {iocResult.type}
                    </Badge>
                  </div>

                  <div className="flex items-center gap-4 pt-4 border-t border-[#1a1a1a]">
                    <div className="flex items-center gap-2">
                      <div className={getVerdictColor(iocResult.verdict)}>
                        {getVerdictIcon(iocResult.verdict)}
                      </div>
                      <div>
                        <div className="text-xs text-gray-400">Verdict</div>
                        <div className={`font-semibold capitalize ${getVerdictColor(iocResult.verdict)}`}>
                          {iocResult.verdict}
                        </div>
                      </div>
                    </div>
                    <div className="flex-1">
                      <div className="text-xs text-gray-400 mb-1">Confidence</div>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-2 bg-[#0a0a0a] rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${iocResult.confidence}%` }}
                            className="h-full bg-gradient-to-r from-[#e43f5a] to-[#e74c3c]"
                            style={{
                              boxShadow: '0 0 10px rgba(228, 63, 90, 0.7)'
                            }}
                          />
                        </div>
                        <span className="text-sm font-mono font-semibold">{iocResult.confidence}%</span>
                      </div>
                    </div>
                  </div>

                  {iocResult.redirectChain && (
                    <div className="pt-4 border-t border-[#1a1a1a]">
                      <div className="text-xs text-gray-400 uppercase tracking-wide mb-3">Redirect Chain</div>
                      <div className="space-y-2">
                        {iocResult.redirectChain.map((url, idx) => (
                          <div key={idx} className="flex items-center gap-2 text-sm">
                            <div className="w-6 h-6 rounded-full bg-[#e43f5a]20 flex items-center justify-center text-xs text-[#e43f5a] font-mono">
                              {idx + 1}
                            </div>
                            <ExternalLink className="w-3 h-3 text-gray-500" />
                            <span className="font-mono text-xs text-gray-300 break-all">{url}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </div>
          </div>
        </motion.div>

        {/* System Health Footer */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-[#0a0a0a] rounded-2xl p-5 border border-[#1a1a1a]"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-green-400" />
                <span className="text-sm text-gray-400">System Status:</span>
                <span className="text-sm font-semibold text-green-400">Operational</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-sm text-gray-400">API: Connected</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-sm text-gray-400">Database: Online</span>
              </div>
            </div>
            <div className="text-xs text-gray-500 font-mono">
              v2.4.1 | Last sync: {currentTime.toLocaleTimeString()}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default function Demo() {
  return <ForensicBrowserMissionControl />;
}
