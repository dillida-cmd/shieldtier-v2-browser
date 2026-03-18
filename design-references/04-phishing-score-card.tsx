/**
 * DESIGN REFERENCE ONLY — Do not import into the app.
 * Template: Email Phishing Analysis Score Card
 * Target: src/renderer/src/components/email/PhishingScoreCard.tsx
 * Source: 21st.dev Magic MCP Builder
 *
 * Key design patterns to extract:
 * - Large risk score with gradient background (green/yellow/red)
 * - Verdict badge (Safe/Suspicious/Malicious)
 * - Category breakdown horizontal bars with animated fill
 * - SPF/DKIM/DMARC authentication badges (pass=green, fail=red, neutral=yellow)
 * - Email headers grid (key:value layout)
 * - Phishing indicators list with severity badges
 * - Scrollable email body preview (monospace)
 */

"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Mail,
  User,
  Clock,
  Server,
  Link as LinkIcon,
  FileText
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

interface PhishingIndicator {
  type: string;
  severity: "high" | "medium" | "low";
  description: string;
}

interface EmailHeader {
  key: string;
  value: string;
}

interface PhishingAnalysisData {
  riskScore: number;
  verdict: "safe" | "suspicious" | "malicious";
  categoryScores: {
    sender: number;
    content: number;
    links: number;
    attachments: number;
  };
  authentication: {
    spf: "pass" | "fail" | "neutral";
    dkim: "pass" | "fail" | "neutral";
    dmarc: "pass" | "fail" | "neutral";
  };
  emailHeaders: EmailHeader[];
  phishingIndicators: PhishingIndicator[];
  emailBody: string;
}

const CustomBadge = ({
  label,
  variant = "primary",
  size = "medium",
  icon,
  className,
}: {
  label: string;
  variant?: "primary" | "secondary" | "success" | "warning" | "error";
  size?: "small" | "medium" | "large";
  icon?: React.ReactNode;
  className?: string;
}) => {
  const variantStyles = {
    primary: "bg-[#2c2c2e] text-white border border-[#3a3a3c]",
    secondary: "bg-[#2c2c2e] text-gray-300 border border-[#3a3a3c]",
    success: "bg-green-600/20 text-green-400 border border-green-600/30",
    warning: "bg-yellow-600/20 text-yellow-400 border border-yellow-600/30",
    error: "bg-red-600/20 text-red-400 border border-red-600/30",
  };

  const sizeStyles = {
    small: "text-xs px-2 py-1",
    medium: "text-sm px-3 py-1.5",
    large: "text-base px-4 py-2",
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className={cn(
        "rounded-md font-medium inline-flex items-center gap-2",
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
    >
      {icon && <span className="flex-shrink-0">{icon}</span>}
      <span className="truncate">{label}</span>
    </motion.div>
  );
};

const PhishingAnalysisScoreCard = ({
  data = {
    riskScore: 78,
    verdict: "suspicious",
    categoryScores: { sender: 65, content: 82, links: 90, attachments: 45 },
    authentication: { spf: "pass", dkim: "fail", dmarc: "neutral" },
    emailHeaders: [
      { key: "From", value: "suspicious@example.com" },
      { key: "To", value: "victim@company.com" },
      { key: "Subject", value: "Urgent: Verify Your Account" },
      { key: "Date", value: "2024-01-15 14:32:18 UTC" },
      { key: "Message-ID", value: "<abc123@mail.example.com>" },
      { key: "Return-Path", value: "bounce@suspicious-domain.com" },
    ],
    phishingIndicators: [
      { type: "Suspicious Link", severity: "high", description: "URL redirects to unknown domain" },
      { type: "Urgency Language", severity: "medium", description: "Contains urgent action phrases" },
      { type: "Sender Mismatch", severity: "high", description: "Display name doesn't match email domain" },
      { type: "Generic Greeting", severity: "low", description: "Uses non-personalized greeting" },
    ],
    emailBody: `Dear Valued Customer,

We have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to verify: http://suspicious-link.example.com/verify

This is an automated message. Please do not reply to this email.

Best regards,
Security Team`,
  } as PhishingAnalysisData,
}: {
  data?: PhishingAnalysisData;
}) => {
  const getRiskColor = (score: number) => {
    if (score < 40) return "text-green-400";
    if (score < 70) return "text-yellow-400";
    return "text-red-400";
  };

  const getRiskBgColor = (score: number) => {
    if (score < 40) return "from-green-600/20 to-green-600/5";
    if (score < 70) return "from-yellow-600/20 to-yellow-600/5";
    return "from-red-600/20 to-red-600/5";
  };

  const getVerdictConfig = (verdict: string) => {
    switch (verdict) {
      case "safe": return { label: "Safe", variant: "success" as const, icon: <CheckCircle2 className="w-4 h-4" /> };
      case "suspicious": return { label: "Suspicious", variant: "warning" as const, icon: <AlertTriangle className="w-4 h-4" /> };
      case "malicious": return { label: "Malicious", variant: "error" as const, icon: <XCircle className="w-4 h-4" /> };
      default: return { label: "Unknown", variant: "secondary" as const, icon: <Shield className="w-4 h-4" /> };
    }
  };

  const getAuthBadgeVariant = (status: string) => {
    switch (status) {
      case "pass": return "success" as const;
      case "fail": return "error" as const;
      default: return "warning" as const;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high": return "text-red-400";
      case "medium": return "text-yellow-400";
      case "low": return "text-blue-400";
      default: return "text-gray-400";
    }
  };

  const verdictConfig = getVerdictConfig(data.verdict);

  return (
    <div className="w-full max-w-4xl mx-auto bg-[#1c1c1e] text-white p-6 rounded-lg space-y-4">
      {/* Risk Score Section */}
      <div className={cn("relative overflow-hidden rounded-lg p-6 bg-gradient-to-br", getRiskBgColor(data.riskScore))}>
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-gray-400" />
              <h2 className="text-lg font-semibold text-gray-300">Phishing Risk Score</h2>
            </div>
            <div className={cn("text-6xl font-bold", getRiskColor(data.riskScore))}>
              {data.riskScore}
            </div>
            <p className="text-sm text-gray-400">out of 100</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <CustomBadge label={verdictConfig.label} variant={verdictConfig.variant} icon={verdictConfig.icon} size="large" />
          </div>
        </div>
      </div>

      {/* Category Scores */}
      <div className="bg-[#2c2c2e] rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Category Breakdown</h3>
        {Object.entries(data.categoryScores).map(([category, score]) => (
          <div key={category} className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-gray-400 capitalize">{category}</span>
              <span className={getRiskColor(score)}>{score}%</span>
            </div>
            <div className="h-2 bg-[#1c1c1e] rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${score}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
                className={cn("h-full rounded-full", score < 40 ? "bg-green-500" : score < 70 ? "bg-yellow-500" : "bg-red-500")}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Authentication Badges */}
      <div className="bg-[#2c2c2e] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Email Authentication</h3>
        <div className="flex flex-wrap gap-2">
          <CustomBadge label={`SPF: ${data.authentication.spf.toUpperCase()}`} variant={getAuthBadgeVariant(data.authentication.spf)} size="small" />
          <CustomBadge label={`DKIM: ${data.authentication.dkim.toUpperCase()}`} variant={getAuthBadgeVariant(data.authentication.dkim)} size="small" />
          <CustomBadge label={`DMARC: ${data.authentication.dmarc.toUpperCase()}`} variant={getAuthBadgeVariant(data.authentication.dmarc)} size="small" />
        </div>
      </div>

      {/* Email Headers Grid */}
      <div className="bg-[#2c2c2e] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Mail className="w-4 h-4" />Email Headers
        </h3>
        <div className="grid grid-cols-1 gap-2 text-xs">
          {data.emailHeaders.map((header, index) => (
            <div key={index} className="grid grid-cols-[120px_1fr] gap-2 py-2 border-b border-[#3a3a3c] last:border-0">
              <span className="text-gray-400 font-medium">{header.key}:</span>
              <span className="text-gray-300 break-all">{header.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Phishing Indicators */}
      <div className="bg-[#2c2c2e] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />Phishing Indicators
        </h3>
        <div className="space-y-2">
          {data.phishingIndicators.map((indicator, index) => (
            <div key={index} className="flex items-start gap-3 p-3 bg-[#1c1c1e] rounded-md">
              <div className={cn("mt-0.5", getSeverityColor(indicator.severity))}>
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium text-gray-300">{indicator.type}</span>
                  <CustomBadge
                    label={indicator.severity}
                    variant={indicator.severity === "high" ? "error" : indicator.severity === "medium" ? "warning" : "primary"}
                    size="small"
                  />
                </div>
                <p className="text-xs text-gray-400">{indicator.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Email Body Preview */}
      <div className="bg-[#2c2c2e] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <FileText className="w-4 h-4" />Email Body Preview
        </h3>
        <ScrollArea className="h-48 w-full rounded-md bg-[#1c1c1e] p-3">
          <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">{data.emailBody}</pre>
        </ScrollArea>
      </div>
    </div>
  );
};

export default function PhishingAnalysisDemo() {
  return (
    <div className="min-h-screen bg-[#0a0a0a] p-8">
      <PhishingAnalysisScoreCard />
    </div>
  );
}
