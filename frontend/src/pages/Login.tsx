import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Mail, Lock, Eye, EyeOff, AlertTriangle, ArrowRight } from 'lucide-react'
import { useAuth } from '../lib/auth'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) { setError('Fill in all fields'); return }
    setError(null)
    setLoading(true)
    try {
      await login(email, password)
      navigate('/')
    } catch {
      setError('Invalid email or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center bg-grid"
      style={{ background: '#0A0D14' }}
    >
      {/* Ambient glow */}
      <div className="fixed pointer-events-none" style={{
        top:'20%', left:'30%', width:'40vw', height:'40vw',
        background:'radial-gradient(circle, rgba(59,130,246,0.07) 0%, transparent 65%)',
        borderRadius:'50%', transform:'translate(-50%,-50%)',
      }} />

      <div className="w-full max-w-md px-6">
        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="flex items-center justify-center rounded-2xl mb-4" style={{
            width:56, height:56,
            background:'linear-gradient(135deg, #3B82F6 0%, #6366F1 100%)',
            boxShadow:'0 0 32px rgba(59,130,246,0.4)',
          }}>
            <Shield size={26} color="#fff" strokeWidth={2.5} />
          </div>
          <h1 className="text-2xl font-bold mb-1" style={{ color:'#F9FAFB' }}>
            SENTINEL<span style={{ color:'#3B82F6' }}>X</span>
          </h1>
          <p className="text-sm" style={{ color:'#6B7280' }}>AI-Powered Security Intelligence</p>
        </div>

        {/* Card */}
        <div className="glass px-8 py-8">
          <h2 className="text-lg font-semibold mb-6" style={{ color:'#F9FAFB' }}>Sign in to your workspace</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div className="relative">
              <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color:'#4B5563' }} />
              <input
                type="email"
                className="sx-input pl-9"
                placeholder="you@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="email"
                disabled={loading}
              />
            </div>

            {/* Password */}
            <div className="relative">
              <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color:'#4B5563' }} />
              <input
                type={showPwd ? 'text' : 'password'}
                className="sx-input pl-9 pr-10"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                disabled={loading}
              />
              <button
                type="button"
                className="absolute right-3 top-1/2 -translate-y-1/2"
                style={{ color:'#4B5563' }}
                onClick={() => setShowPwd(!showPwd)}
                tabIndex={-1}
              >
                {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
                style={{ background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.2)', color:'#FCA5A5' }}>
                <AlertTriangle size={13} />
                {error}
              </div>
            )}

            <button type="submit" className="sx-btn w-full justify-center" disabled={loading}>
              {loading ? <><span className="spin">⊙</span> Signing in…</> : <>Sign In <ArrowRight size={14} /></>}
            </button>
          </form>

          <p className="text-center text-xs mt-6" style={{ color:'#6B7280' }}>
            No account?{' '}
            <Link to="/register" className="hover:underline" style={{ color:'#3B82F6' }}>
              Create one
            </Link>
          </p>
        </div>

        <p className="text-center text-xs mt-6" style={{ color:'#374151' }}>
          SentinelX · AI Security Intelligence Platform
        </p>
      </div>
    </div>
  )
}
