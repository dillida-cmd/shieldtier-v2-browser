/**
 * DESIGN REFERENCE ONLY — Do not import into the app.
 * Template: Premium Login Screen
 * Target: src/renderer/src/components/LoginScreen.tsx
 * Source: 21st.dev Magic MCP Builder + Inspiration
 *
 * Key design patterns to extract:
 * - Full-screen dark background with centered glass card
 * - Shield logo with gradient glow (blue→purple radial)
 * - Password strength indicator bar (weak/medium/strong)
 * - Gradient brand button with glow shadow
 * - Enhanced glass morphism (stronger blur, inner glow border)
 * - Input focus states with accent glow ring
 * - Animated particle/grid background (optional)
 * - Register view with analyst name + confirm password
 * - E2E encryption tagline footer
 */

"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Mail,
  Lock,
  Eye,
  EyeOff,
  User,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";

type AuthView = "login" | "register" | "verify-pending";

// Password strength calculator
function getPasswordStrength(password: string): { score: number; label: string; color: string } {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 1) return { score: 20, label: "Weak", color: "#ff453a" };
  if (score <= 2) return { score: 40, label: "Fair", color: "#ff9f0a" };
  if (score <= 3) return { score: 60, label: "Medium", color: "#ffd60a" };
  if (score <= 4) return { score: 80, label: "Strong", color: "#30d158" };
  return { score: 100, label: "Very Strong", color: "#30d158" };
}

export default function LoginScreenDesignReference() {
  const [view, setView] = useState<AuthView>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [analystName, setAnalystName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const strength = getPasswordStrength(password);

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center overflow-hidden"
      style={{ background: "#1c1c1e" }}
    >
      {/* Animated background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full opacity-20 blur-[120px]"
          style={{
            background: "radial-gradient(circle, #0a84ff 0%, #bf5af2 50%, transparent 70%)",
          }}
        />
        {/* Grid lines */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
            backgroundSize: "40px 40px",
          }}
        />
      </div>

      {/* Glass card */}
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="relative w-[440px] max-w-[90vw] rounded-2xl overflow-hidden"
        style={{
          background: "rgba(44, 44, 46, 0.8)",
          backdropFilter: "blur(40px) saturate(180%)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          boxShadow: `
            0 0 0 1px rgba(255, 255, 255, 0.05) inset,
            0 24px 48px rgba(0, 0, 0, 0.4),
            0 0 80px rgba(10, 132, 255, 0.08)
          `,
        }}
      >
        {/* Header — Logo + Title */}
        <div className="px-8 pt-8 pb-4 text-center">
          {/* Shield logo with gradient glow */}
          <div className="relative flex justify-center mb-5">
            <div
              className="absolute w-20 h-20 rounded-full blur-[30px] opacity-40"
              style={{
                background: "radial-gradient(circle, #0a84ff, #bf5af2)",
              }}
            />
            <svg width="52" height="52" viewBox="0 0 32 32" fill="none" className="relative z-10">
              <defs>
                <linearGradient id="shieldGradLogin" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#0a84ff" />
                  <stop offset="100%" stopColor="#bf5af2" />
                </linearGradient>
              </defs>
              <path
                d="M16 2L4 8v8c0 7.7 5.1 14.9 12 16 6.9-1.1 12-8.3 12-16V8L16 2z"
                fill="url(#shieldGradLogin)"
                opacity="0.15"
              />
              <path
                d="M16 2L4 8v8c0 7.7 5.1 14.9 12 16 6.9-1.1 12-8.3 12-16V8L16 2z"
                stroke="url(#shieldGradLogin)"
                strokeWidth="1.5"
                fill="none"
              />
              <path
                d="M12 16l3 3 5-6"
                stroke="url(#shieldGradLogin)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                fill="none"
              />
            </svg>
          </div>

          <h2 className="text-lg font-bold text-[#e5e5e7] mb-1">
            {view === "login" && "Sign in to ShieldTier"}
            {view === "register" && "Create Your Account"}
            {view === "verify-pending" && "Check Your Email"}
          </h2>
          <p className="text-xs text-[#636366]">
            {view === "login" && "SOC investigation platform with E2E encrypted collaboration"}
            {view === "register" && "Set up your analyst account to get started"}
            {view === "verify-pending" && "We sent a verification link to your email"}
          </p>
        </div>

        {/* Login Form */}
        <AnimatePresence mode="wait">
          {view === "login" && (
            <motion.div
              key="login"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="px-8 py-4 space-y-4"
            >
              {/* Email */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@example.com"
                    className="w-full h-10 pl-10 pr-4 rounded-xl text-[13px] font-mono
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    className="w-full h-10 pl-10 pr-10 rounded-xl text-[13px]
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#636366] hover:text-[#98989d] transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="text-xs text-[#ff453a] bg-[#ff453a]/10 border border-[#ff453a]/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              {/* Sign In Button */}
              <button
                disabled={loading}
                className="w-full h-10 rounded-xl text-[13px] font-semibold text-white
                  transition-all duration-200 cursor-pointer
                  disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, #0a84ff, #bf5af2)",
                  boxShadow: "0 0 20px rgba(10, 132, 255, 0.3), 0 0 40px rgba(191, 90, 242, 0.15)",
                }}
              >
                {loading ? "Signing in..." : "Sign In"}
              </button>

              {/* Register Link */}
              <div className="text-center">
                <button
                  onClick={() => { setView("register"); setError(""); }}
                  className="text-xs text-[#0a84ff] hover:text-[#3a9fff] transition-colors cursor-pointer"
                >
                  Don't have an account? Create one
                </button>
              </div>
            </motion.div>
          )}

          {view === "register" && (
            <motion.div
              key="register"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="px-8 py-4 space-y-4"
            >
              {/* Email */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@example.com"
                    className="w-full h-10 pl-10 pr-4 rounded-xl text-[13px] font-mono
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                </div>
              </div>

              {/* Analyst Name */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Analyst Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type="text"
                    value={analystName}
                    onChange={(e) => setAnalystName(e.target.value)}
                    placeholder="e.g. Jane Smith"
                    className="w-full h-10 pl-10 pr-4 rounded-xl text-[13px]
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                </div>
              </div>

              {/* Password with strength indicator */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Minimum 8 characters"
                    className="w-full h-10 pl-10 pr-10 rounded-xl text-[13px]
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#636366] hover:text-[#98989d]"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {/* Password Strength Bar */}
                {password.length > 0 && (
                  <div className="mt-2 space-y-1">
                    <div className="h-1 bg-[#38383a] rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${strength.score}%` }}
                        transition={{ duration: 0.3 }}
                        className="h-full rounded-full"
                        style={{ backgroundColor: strength.color }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px]">
                      <span style={{ color: strength.color }}>{strength.label}</span>
                      <span className="text-[#636366]">{strength.score}%</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-xs text-[#98989d] mb-1.5">Confirm Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#636366]" />
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm your password"
                    className="w-full h-10 pl-10 pr-4 rounded-xl text-[13px]
                      bg-[#1c1c1e] border border-[#38383a] text-[#e5e5e7]
                      placeholder:text-[#636366]
                      focus:outline-none focus:border-[#0a84ff]
                      focus:shadow-[0_0_0_3px_rgba(10,132,255,0.15)]
                      transition-all duration-200"
                  />
                </div>
                {confirmPassword && password !== confirmPassword && (
                  <p className="text-[10px] text-[#ff453a] mt-1">Passwords do not match</p>
                )}
              </div>

              {/* Error */}
              {error && (
                <div className="text-xs text-[#ff453a] bg-[#ff453a]/10 border border-[#ff453a]/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              {/* Create Account Button */}
              <button
                disabled={loading}
                className="w-full h-10 rounded-xl text-[13px] font-semibold text-white
                  transition-all duration-200 cursor-pointer
                  disabled:opacity-50"
                style={{
                  background: "linear-gradient(135deg, #0a84ff, #bf5af2)",
                  boxShadow: "0 0 20px rgba(10, 132, 255, 0.3), 0 0 40px rgba(191, 90, 242, 0.15)",
                }}
              >
                {loading ? "Creating Account..." : "Create Account"}
              </button>

              {/* Back to Login */}
              <div className="text-center">
                <button
                  onClick={() => { setView("login"); setError(""); }}
                  className="text-xs text-[#0a84ff] hover:text-[#3a9fff] transition-colors cursor-pointer"
                >
                  Already have an account? Sign in
                </button>
              </div>
            </motion.div>
          )}

          {view === "verify-pending" && (
            <motion.div
              key="verify"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="px-8 py-8 text-center space-y-4"
            >
              <CheckCircle2 className="w-12 h-12 text-[#30d158] mx-auto opacity-60" />
              <p className="text-sm text-[#98989d]">
                We sent a verification link to{" "}
                <span className="text-[#0a84ff] font-medium">{email}</span>.
              </p>
              <p className="text-xs text-[#636366]">
                Click the link in your email to activate your account.
              </p>
              <button
                onClick={() => { setView("login"); setError(""); }}
                className="text-xs text-[#0a84ff] hover:text-[#3a9fff] cursor-pointer"
              >
                Back to Sign In
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Footer */}
        <div className="px-8 pb-6 pt-2 text-center">
          <p className="text-[10px] text-[#636366] opacity-60">
            ShieldTier™ — End-to-end encrypted. Zero-knowledge cloud.
          </p>
        </div>
      </motion.div>
    </div>
  );
}
