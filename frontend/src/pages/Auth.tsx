import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Mail, Lock, Eye, EyeOff, Check } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { api } from '../lib/api'
import { COLOR } from '../lib/theme'

const BULLETS = [
  'Explainable AI-driven pentest decisions',
  'Validated findings — confirmed, not guessed',
  'Intelligence-Driven threat analysis',
]

export default function Auth() {
  const [mode, setMode]       = useState<'login' | 'register'>('login')
  const [email, setEmail]     = useState('')
  const [password, setPwd]    = useState('')
  const [confirm, setConfirm] = useState('')
  const [fullName, setName]   = useState('')
  const [showPwd, setShow]    = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState<string | null>(null)

  const { login } = useAuth()
  const navigate  = useNavigate()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) { setError('All fields are required'); return }
    if (mode === 'register' && password !== confirm) { setError('Passwords do not match'); return }

    setError(null)
    setLoading(true)
    try {
      if (mode === 'login') {
        await login(email, password)
      } else {
        await api.register(email, password, fullName || undefined)
      }
      navigate('/')
    } catch {
      setError(mode === 'login' ? 'Invalid email or password' : 'Registration failed — account may already exist')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex" style={{ background: COLOR.bg.base }}>

      {/* Left panel — 40% */}
      <div
        className="hidden md:flex flex-col justify-center px-12"
        style={{ width: '40%', background: COLOR.bg.surface, borderRight: `1px solid ${COLOR.bg.border}` }}
      >
        {/* Logo */}
        <div className="mb-10">
          <div className="flex items-center gap-3 mb-4">
            <div
              className="flex items-center justify-center rounded-xl"
              style={{
                width: 44, height: 44,
                background: `linear-gradient(135deg, ${COLOR.green['700']} 0%, ${COLOR.green['300']} 100%)`,
                boxShadow: `0 0 24px ${COLOR.green.glow}`,
              }}
            >
              <Shield size={22} color={COLOR.bg.base} strokeWidth={2.5} />
            </div>
            <h1 className="text-2xl font-bold" style={{ color: COLOR.text.primary, letterSpacing: '-0.02em' }}>
              SENTINEL<span style={{ color: COLOR.accent }}>X</span>
            </h1>
          </div>
          <p className="text-sm leading-relaxed" style={{ color: COLOR.text.secondary, maxWidth: 300 }}>
            Explainable. Validated. Intelligence&#8209;Driven.
          </p>
        </div>

        {/* Feature bullets */}
        <div className="space-y-4">
          {BULLETS.map((b) => (
            <div key={b} className="flex items-start gap-3">
              <div
                className="flex items-center justify-center rounded-full flex-shrink-0"
                style={{ width: 20, height: 20, background: 'rgba(46,165,95,0.15)', marginTop: 1 }}
              >
                <Check size={11} style={{ color: COLOR.accent }} />
              </div>
              <span className="text-sm" style={{ color: COLOR.text.secondary }}>{b}</span>
            </div>
          ))}
        </div>

        <div className="mt-12 pt-8" style={{ borderTop: `1px solid ${COLOR.bg.border}` }}>
          <p className="text-xs" style={{ color: COLOR.text.muted }}>
            AI-Powered Security Intelligence Platform · Phase 3
          </p>
        </div>
      </div>

      {/* Right panel — 60% */}
      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full" style={{ maxWidth: 400 }}>

          {/* Mobile logo */}
          <div className="md:hidden flex items-center gap-3 mb-8">
            <Shield size={24} style={{ color: COLOR.accent }} />
            <span className="text-xl font-bold" style={{ color: COLOR.text.primary }}>
              SENTINEL<span style={{ color: COLOR.accent }}>X</span>
            </span>
          </div>

          {/* Tab toggle */}
          <div
            className="flex mb-6 rounded-lg p-1"
            style={{ background: COLOR.bg.surface, border: `1px solid ${COLOR.bg.border}` }}
          >
            {(['login', 'register'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => { setMode(tab); setError(null) }}
                className="flex-1 py-2 rounded text-sm font-semibold capitalize transition-all"
                style={{
                  background: mode === tab ? COLOR.green['500'] : 'transparent',
                  color: mode === tab ? COLOR.bg.base : COLOR.text.muted,
                  border: 'none',
                  cursor: 'pointer',
                }}
              >
                {tab === 'login' ? 'Sign In' : 'Register'}
              </button>
            ))}
          </div>

          <h2 className="text-lg font-semibold mb-6" style={{ color: COLOR.text.primary }}>
            {mode === 'login' ? 'Sign in to your workspace' : 'Create your account'}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-3">
            {mode === 'register' && (
              <div>
                <label className="block text-xs font-semibold mb-1.5" style={{ color: COLOR.text.muted }}>Full Name (optional)</label>
                <input
                  type="text"
                  className="sx-input"
                  placeholder="Jane Doe"
                  value={fullName}
                  onChange={(e) => setName(e.target.value)}
                  disabled={loading}
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: COLOR.text.muted }}>Email</label>
              <div className="relative">
                <Mail size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: COLOR.text.muted }} />
                <input
                  type="email"
                  className="sx-input"
                  style={{ paddingLeft: 34 }}
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  disabled={loading}
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5" style={{ color: COLOR.text.muted }}>Password</label>
              <div className="relative">
                <Lock size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: COLOR.text.muted }} />
                <input
                  type={showPwd ? 'text' : 'password'}
                  className="sx-input"
                  style={{ paddingLeft: 34, paddingRight: 40 }}
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPwd(e.target.value)}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  disabled={loading}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: COLOR.text.muted }}
                  onClick={() => setShow(!showPwd)}
                  tabIndex={-1}
                >
                  {showPwd ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            {mode === 'register' && (
              <div>
                <label className="block text-xs font-semibold mb-1.5" style={{ color: COLOR.text.muted }}>Confirm Password</label>
                <div className="relative">
                  <Lock size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: COLOR.text.muted }} />
                  <input
                    type={showPwd ? 'text' : 'password'}
                    className="sx-input"
                    style={{
                      paddingLeft: 34,
                      borderColor: confirm && confirm !== password ? COLOR.danger : undefined,
                    }}
                    placeholder="Confirm password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    autoComplete="new-password"
                    disabled={loading}
                  />
                </div>
                {confirm && confirm !== password && (
                  <p className="text-xs mt-1" style={{ color: COLOR.danger }}>Passwords do not match</p>
                )}
              </div>
            )}

            {error && (
              <div className="px-3 py-2 rounded-lg text-xs" style={{ background: 'rgba(229,59,59,0.08)', border: '1px solid rgba(229,59,59,0.2)', color: '#fca5a5' }}>
                {error}
              </div>
            )}

            <button type="submit" className="btn-primary w-full justify-center mt-2" disabled={loading}>
              {loading
                ? <><span className="spin" style={{ display: 'inline-block', marginRight: 6 }}>⊙</span> {mode === 'login' ? 'Signing in…' : 'Creating account…'}</>
                : mode === 'login' ? 'Sign In' : 'Create Account'
              }
            </button>
          </form>

          <p className="text-center text-xs mt-6" style={{ color: COLOR.text.muted }}>
            {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            <button
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
              style={{ color: COLOR.accent, background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}
            >
              {mode === 'login' ? 'Register' : 'Sign In'}
            </button>
          </p>
        </div>
      </div>
    </div>
  )
}
