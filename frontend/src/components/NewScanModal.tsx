import React, { useState, useRef, useEffect } from 'react'
import {
  X, Globe, Zap, ShieldCheck, Lock, ChevronDown, ChevronUp, AlertTriangle,
} from 'lucide-react'
import { api, type ScanType, type AuthConfig } from '../lib/api'
import { COLOR } from '../lib/theme'

interface Props {
  onClose: () => void
  onLaunched: (scanId: string) => void
  isPro: boolean
}

type AuthType = 'none' | 'cookie' | 'bearer' | 'basic'

export default function NewScanModal({ onClose, onLaunched, isPro }: Props) {
  const [domain, setDomain]             = useState('')
  const [scanType, setScanType]         = useState<ScanType>('passive')
  const [scanMode, setScanMode]         = useState<'deterministic' | 'adaptive'>('adaptive')
  const [authType, setAuthType]         = useState<AuthType>('none')
  const [authOpen, setAuthOpen]         = useState(false)
  const [cookie, setCookie]             = useState('')
  const [token, setToken]               = useState('')
  const [username, setUsername]         = useState('')
  const [password, setPassword]         = useState('')
  const [authConfirmed, setAuthConfirmed] = useState(false)
  const [isLaunching, setIsLaunching]   = useState(false)
  const [error, setError]               = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  const SCAN_TYPES: Array<{ type: ScanType; label: string; desc: string; icon: React.ElementType; proOnly: boolean }> = [
    { type: 'passive', label: 'Quick Recon',    desc: 'Passive — no active traffic',  icon: Globe,       proOnly: false },
    { type: 'active',  label: 'Active Pentest', desc: 'Active scanning, AI-selected', icon: Zap,         proOnly: true  },
    { type: 'full',    label: 'Full Pentest',   desc: 'Passive + active combined',     icon: ShieldCheck, proOnly: true  },
  ]

  function buildAuthConfig(): AuthConfig | undefined {
    if (authType === 'none') return undefined
    if (authType === 'cookie')  return { type: 'cookie', cookie }
    if (authType === 'bearer')  return { type: 'bearer', token }
    if (authType === 'basic')   return { type: 'basic', username, password }
  }

  async function handleLaunch() {
    if (!domain.trim()) { setError('Enter a target domain'); return }
    if (scanType !== 'passive' && !authConfirmed) {
      setError('You must confirm authorization before active scanning')
      return
    }
    setError(null)
    setIsLaunching(true)
    try {
      const scan = await api.createScan({
        domain: domain.trim(),
        scan_type: scanType,
        scan_mode: scanType !== 'passive' ? scanMode : undefined,
        authorization_confirmed: authConfirmed,
        auth_config: buildAuthConfig(),
      })
      onLaunched(scan.id)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Failed to launch scan'
      setError(msg)
      setIsLaunching(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.72)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        className="card w-full relative overflow-y-auto"
        style={{ maxWidth: 500, maxHeight: '90vh', padding: '28px 32px', background: COLOR.bg.raised }}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="font-bold text-base" style={{ color: COLOR.text.primary }}>New Security Assessment</h2>
            <p className="text-xs mt-0.5" style={{ color: COLOR.text.muted }}>
              AI orchestrator selects tools dynamically based on live findings
            </p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: COLOR.text.muted }}>
            <X size={17} />
          </button>
        </div>

        {/* Target */}
        <div className="mb-5">
          <label className="block text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: COLOR.text.muted }}>
            Target Domain
          </label>
          <div className="relative">
            <Globe size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: COLOR.text.muted }} />
            <input
              ref={inputRef}
              type="text"
              className="sx-input"
              style={{ paddingLeft: 34 }}
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLaunch()}
              disabled={isLaunching}
              spellCheck={false}
              autoComplete="off"
            />
          </div>
        </div>

        {/* Scan type */}
        <div className="mb-4">
          <label className="block text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: COLOR.text.muted }}>
            Scan Type
          </label>
          <div className="grid grid-cols-3 gap-2">
            {SCAN_TYPES.map(({ type, label, desc, icon: Icon, proOnly }) => {
              const locked   = proOnly && !isPro
              const selected = scanType === type
              return (
                <button
                  key={type}
                  onClick={() => !locked && setScanType(type)}
                  className="flex flex-col items-start gap-1 p-3 rounded-lg text-left transition-all"
                  style={{
                    background: selected ? 'rgba(46,165,95,0.08)' : COLOR.bg.surface,
                    border: selected ? '1px solid rgba(46,165,95,0.35)' : `1px solid ${COLOR.bg.border}`,
                    cursor: locked ? 'not-allowed' : 'pointer',
                    opacity: locked ? 0.55 : 1,
                  }}
                >
                  {locked
                    ? <Lock size={12} style={{ color: COLOR.text.muted }} />
                    : <Icon size={12} style={{ color: selected ? COLOR.accent : COLOR.text.muted }} />
                  }
                  <div className="text-xs font-semibold" style={{ color: selected ? COLOR.text.primary : COLOR.slate['200'] }}>
                    {label}
                  </div>
                  <div className="text-xs" style={{ color: COLOR.text.muted, fontSize: 10 }}>{desc}</div>
                  {locked && (
                    <span className="text-xs px-1 py-0.5 rounded font-bold" style={{ background: 'rgba(196,150,42,0.12)', color: COLOR.warn, fontSize: 9 }}>
                      PRO
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        </div>

        {/* Scan mode */}
        {scanType !== 'passive' && (
          <div className="mb-4">
            <label className="block text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: COLOR.text.muted }}>
              Execution Mode
            </label>
            <div className="flex gap-2">
              {(['deterministic', 'adaptive'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setScanMode(mode)}
                  className="px-3 py-1.5 rounded text-xs font-semibold capitalize transition-all"
                  style={{
                    background: scanMode === mode ? 'rgba(74,109,130,0.12)' : COLOR.bg.surface,
                    border: scanMode === mode ? `1px solid ${COLOR.slate['400']}` : `1px solid ${COLOR.bg.border}`,
                    color: scanMode === mode ? COLOR.slate['200'] : COLOR.text.muted,
                    cursor: 'pointer',
                  }}
                >
                  {mode}
                </button>
              ))}
              <span className="self-center text-xs" style={{ color: COLOR.text.muted }}>
                {scanMode === 'adaptive' ? '— LLM picks tools dynamically' : '— fixed tool sequence'}
              </span>
            </div>
          </div>
        )}

        {/* Auth config accordion */}
        <div className="mb-4">
          <button
            className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all"
            style={{ background: COLOR.bg.surface, border: `1px solid ${COLOR.bg.border}`, color: COLOR.text.muted, cursor: 'pointer' }}
            onClick={() => setAuthOpen(!authOpen)}
          >
            <span>Auth Configuration</span>
            {authOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>

          {authOpen && (
            <div className="mt-2 p-3 rounded-lg" style={{ background: COLOR.bg.surface, border: `1px solid ${COLOR.bg.border}` }}>
              {/* Type selector */}
              <div className="flex gap-2 mb-3">
                {(['none', 'cookie', 'bearer', 'basic'] as AuthType[]).map((t) => (
                  <button
                    key={t}
                    onClick={() => setAuthType(t)}
                    className="px-2.5 py-1 rounded text-xs font-semibold capitalize transition-all"
                    style={{
                      background: authType === t ? 'rgba(46,165,95,0.12)' : 'transparent',
                      border: authType === t ? `1px solid rgba(46,165,95,0.3)` : `1px solid ${COLOR.bg.border}`,
                      color: authType === t ? COLOR.accent : COLOR.text.muted,
                      cursor: 'pointer',
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>

              {authType === 'cookie' && (
                <textarea
                  className="sx-input"
                  style={{ height: 72, resize: 'none' }}
                  placeholder="Cookie: session=abc123; csrftoken=xyz"
                  value={cookie}
                  onChange={(e) => setCookie(e.target.value)}
                />
              )}
              {authType === 'bearer' && (
                <input
                  type="text"
                  className="sx-input"
                  placeholder="Bearer token"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
              )}
              {authType === 'basic' && (
                <div className="space-y-2">
                  <input type="text" className="sx-input" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
                  <input type="password" className="sx-input" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
              )}
            </div>
          )}
        </div>

        {/* Auth warning */}
        {scanType !== 'passive' && (
          <div className="flex items-start gap-2.5 mb-4 p-3 rounded-lg" style={{ background: 'rgba(229,59,59,0.05)', border: '1px solid rgba(229,59,59,0.18)' }}>
            <input
              type="checkbox"
              id="auth-confirm"
              checked={authConfirmed}
              onChange={(e) => setAuthConfirmed(e.target.checked)}
              className="mt-0.5 cursor-pointer"
              style={{ accentColor: COLOR.accent, width: 14, height: 14 }}
            />
            <label htmlFor="auth-confirm" className="text-xs cursor-pointer leading-relaxed" style={{ color: '#fca5a5' }}>
              I confirm I have written authorization to perform active scanning on this target.
              Only scan targets you own or have explicit permission to test.
            </label>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="mb-4 flex items-center gap-2 px-3 py-2 rounded-lg text-xs" style={{ background: 'rgba(229,59,59,0.07)', border: '1px solid rgba(229,59,59,0.2)', color: '#fca5a5' }}>
            <AlertTriangle size={12} />
            {error}
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button className="btn-primary flex-1 justify-center" onClick={handleLaunch} disabled={isLaunching || !domain.trim()}>
            {isLaunching ? <><span className="spin" style={{ display: 'inline-block' }}>⊙</span> Launching…</> : 'Start Scan'}
          </button>
          <button className="btn-ghost px-5" onClick={onClose} disabled={isLaunching}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}
