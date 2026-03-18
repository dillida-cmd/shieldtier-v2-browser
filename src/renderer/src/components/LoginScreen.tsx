import React, { useState, useEffect, useRef } from 'react';
import type { AuthUser } from '../types';
import { Button } from './ui/button';
import { Input } from './ui/input';

type LoginView = 'login' | 'register' | 'verify-pending';

interface LoginScreenProps {
  onAuthenticated: (user: AuthUser) => void;
}

export function LoginScreen({ onAuthenticated }: LoginScreenProps) {
  const [view, setView] = useState<LoginView>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [analystName, setAnalystName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
  }, [view]);

  const handleLogin = async () => {
    if (!email.trim() || !password) {
      setError('Email and password are required');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const result = await window.shieldtier.auth.login(email.trim(), password);
      if (result.success && result.user) {
        onAuthenticated(result.user);
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!email.trim() || !password || !analystName.trim()) {
      setError('All fields are required');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const result = await window.shieldtier.auth.register(email.trim(), password, analystName.trim());
      if (result.success) {
        // Auto-login after registration
        const loginResult = await window.shieldtier.auth.login(email.trim(), password);
        if (loginResult.success && loginResult.user) {
          onAuthenticated(loginResult.user);
        } else {
          // Fallback to login screen if auto-login fails
          setView('login');
          setError('Account created. Please sign in.');
        }
      } else {
        setError(result.error || 'Registration failed');
      }
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (view === 'login') handleLogin();
      else if (view === 'register') handleRegister();
    }
  };

  return (
    <div className="fixed inset-0 z-[60] bg-[color:var(--st-bg-base)] flex items-center justify-center"
         style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}>
      <div className="glass rounded-xl border w-[440px] max-w-[90vw] dialog-enter"
           style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="px-6 pt-6 pb-2 text-center">
          <div className="flex justify-center mb-4">
            <svg width="48" height="48" viewBox="0 0 32 32" fill="none">
              <defs>
                <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="var(--st-info)" />
                  <stop offset="100%" stopColor="var(--st-purple)" />
                </linearGradient>
              </defs>
              <path d="M16 2L4 8v8c0 7.7 5.1 14.9 12 16 6.9-1.1 12-8.3 12-16V8L16 2z" fill="url(#shieldGrad)" opacity="0.2"/>
              <path d="M16 2L4 8v8c0 7.7 5.1 14.9 12 16 6.9-1.1 12-8.3 12-16V8L16 2z" stroke="url(#shieldGrad)" strokeWidth="1.5" fill="none"/>
              <path d="M12 16l3 3 5-6" stroke="url(#shieldGrad)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
            </svg>
          </div>
          <h2 className="block text-lg font-bold text-[color:var(--st-text-primary)] mb-1">
            {view === 'login' && 'Sign in to ShieldTier'}
            {view === 'register' && 'Create Your Account'}
            {view === 'verify-pending' && 'Check Your Email'}
          </h2>
          <p className="block text-xs text-[color:var(--st-text-muted)]">
            {view === 'login' && 'SOC investigation platform with E2E encrypted collaboration'}
            {view === 'register' && 'Set up your analyst account to get started'}
            {view === 'verify-pending' && 'We sent a verification link to your email'}
          </p>
        </div>

        {/* Login Form */}
        {view === 'login' && (
          <div className="px-6 py-4 space-y-3">
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Email</label>
              <Input
                ref={emailRef}
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="analyst@example.com"
                autoComplete="email"
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Password</label>
              <Input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </div>

            {error && (
              <div role="alert" aria-live="assertive" className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {error}
              </div>
            )}

            <Button
              onClick={handleLogin}
              disabled={loading}
              className="w-full"
              style={{ background: loading ? undefined : 'var(--st-gradient-brand)' }}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>

            <div className="text-center">
              <Button
                variant="link"
                size="sm"
                onClick={() => { setView('register'); setError(''); }}
              >
                Don't have an account? Create one
              </Button>
            </div>
          </div>
        )}

        {/* Register Form */}
        {view === 'register' && (
          <div className="px-6 py-4 space-y-3">
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Email</label>
              <Input
                ref={emailRef}
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="analyst@example.com"
                autoComplete="email"
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Analyst Name</label>
              <Input
                type="text"
                value={analystName}
                onChange={e => setAnalystName(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="e.g. Jane Smith"
                maxLength={80}
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Password</label>
              <Input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Minimum 8 characters"
                autoComplete="new-password"
              />
            </div>
            <div>
              <label className="block text-xs text-[color:var(--st-text-muted)] mb-1">Confirm Password</label>
              <Input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Confirm your password"
                autoComplete="new-password"
              />
            </div>

            {error && (
              <div role="alert" aria-live="assertive" className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {error}
              </div>
            )}

            <Button
              onClick={handleRegister}
              disabled={loading}
              className="w-full"
              style={{ background: loading ? undefined : 'var(--st-gradient-brand)' }}
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </Button>

            <div className="text-center">
              <Button
                variant="link"
                size="sm"
                onClick={() => { setView('login'); setError(''); }}
              >
                Already have an account? Sign in
              </Button>
            </div>
          </div>
        )}

        {/* Verify Pending */}
        {view === 'verify-pending' && (
          <div className="px-6 py-6 text-center space-y-4">
            <div className="text-4xl opacity-30">&#9993;</div>
            <p className="text-sm text-[color:var(--st-text-secondary)]">
              We sent a verification link to <span className="text-[color:var(--st-accent)] font-medium">{email}</span>.
            </p>
            <p className="text-xs text-[color:var(--st-text-muted)]">
              Click the link in your email to activate your account, then come back here to sign in.
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => { setView('login'); setError(''); }}
            >
              Back to Sign In
            </Button>
          </div>
        )}

        {/* Footer */}
        <div className="px-6 pb-4 pt-1 text-center">
          <p className="text-[10px] text-[color:var(--st-text-muted)] opacity-60">
            ShieldTier{'\u2122'} — End-to-end encrypted. Zero-knowledge cloud.
          </p>
        </div>
      </div>
    </div>
  );
}
