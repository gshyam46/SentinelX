import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, AlertTriangle, ShieldCheck, Play,
  Zap, Lock, ChevronRight, Globe, Clock,
  TrendingUp, Target, BarChart3,
} from 'lucide-react'
import { api, type ScanStatusResponse, type ScanType } from '@/lib/api'
import { riskColor, formatRelativeTime } from '@/lib/utils'

// ── Mock stats for demo when API not connected ────────────────────────
const DEMO_STATS = { totalScans: 147, criticalFindings: 23, assetsProtected: 12 }
const DEMO_SCANS: ScanStatusResponse[] = [
  { id: 'a1b2', domain: 'api.corp.internal',     scan_type: 'active',  status: 'complete', progress: 100, created_at: new Date(Date.now() - 7_200_000).toISOString() },
  { id: 'c3d4', domain: 'staging.saas.io',       scan_type: 'passive', status: 'running',  progress: 62,  created_at: new Date(Date.now() -   900_000).toISOString() },
  { id: 'e5f6', domain: 'checkout.payments.com', scan_type: 'full',    status: 'complete', progress: 100, created_at: new Date(Date.now() - 86_400_000).toISOString() },
  { id: 'g7h8', domain: 'dev.example.com',       scan_type: 'passive', status: 'failed',   progress: 0,   created_at: new Date(Date.now() - 172_800_000).toISOString() },
]
const DEMO_RISK: Record<string, number> = { a1b2: 82, c3d4: 47, e5f6: 31, g7h8: 0 }

export default function Dashboard() {
  const navigate = useNavigate()
  const [domain, setDomain] = useState('')
  const [scanType, setScanType] = useState<ScanType>('passive')
  const [authConfirmed, setAuthConfirmed] = useState(false)
  const [isLaunching, setIsLaunching] = useState(false)
  const [scans, setScans] = useState<ScanStatusResponse[]>(DEMO_SCANS)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Focus input on mount
  useEffect(() => { inputRef.current?.focus() }, [])

  // Poll recent scans
  useEffect(() => {
    let alive = true
    const fetchScans = async () => {
      try {
        const data = await api.listScans(0, 10)
        if (alive) setScans(data.scans)
      } catch {
        // Use demo data if API not available
      }
    }
    fetchScans()
    const id = setInterval(fetchScans, 10_000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  async function handleLaunch() {
    if (!domain.trim()) {
      setError('Enter a target domain')
      inputRef.current?.focus()
      return
    }
    if (scanType === 'active' && !authConfirmed) {
      setError('You must confirm you have authorization to scan this target')
      return
    }
    setError(null)
    setIsLaunching(true)

    try {
      const scan = await api.createScan({
        domain: domain.trim(),
        scan_type: scanType,
        authorization_confirmed: authConfirmed,
      })
      navigate(`/scans/${scan.id}`)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Failed to launch scan'
      setError(msg)
      setIsLaunching(false)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter') handleLaunch()
  }

  const isPro = false // replace with actual user tier from auth context

  return (
    <div className="px-8 py-8 max-w-7xl">
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold mb-1" style={{ color: '#F9FAFB' }}>
          Security Command Center
        </h1>
        <p className="text-sm" style={{ color: '#6B7280' }}>
          Agentic reconnaissance and vulnerability assessment · Powered by SentinelX AI
        </p>
      </div>

      {/* ── Stats bar ── */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {[
          {
            label: 'Total Scans',
            value: DEMO_STATS.totalScans,
            icon: BarChart3,
            color: '#3B82F6',
            sub: '+8 this week',
          },
          {
            label: 'Critical Findings',
            value: DEMO_STATS.criticalFindings,
            icon: AlertTriangle,
            color: '#EF4444',
            sub: '3 unresolved',
          },
          {
            label: 'Assets Monitored',
            value: DEMO_STATS.assetsProtected,
            icon: ShieldCheck,
            color: '#22C55E',
            sub: 'All scanned',
          },
        ].map(({ label, value, icon: Icon, color, sub }) => (
          <div
            key={label}
            className="glass flex items-center gap-4 px-5 py-4"
            style={{ transition: 'border-color 0.2s' }}
            onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = color + '40')}
            onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = '#1F2937')}
          >
            <div
              className="flex items-center justify-center rounded-lg shrink-0"
              style={{ width: 40, height: 40, background: `${color}15` }}
            >
              <Icon size={18} style={{ color }} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color }}>{value}</div>
              <div className="text-xs mt-0.5" style={{ color: '#6B7280' }}>{label}</div>
              <div className="text-xs mt-0.5" style={{ color: '#4B5563' }}>{sub}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Launch scan form ── */}
      <div
        className="glass mb-8 relative overflow-hidden"
        style={{ padding: '32px 36px' }}
      >
        {/* Background decoration */}
        <div
          className="absolute top-0 right-0 pointer-events-none"
          style={{
            width: 300, height: 300,
            background: 'radial-gradient(circle, rgba(59,130,246,0.05) 0%, transparent 70%)',
            transform: 'translate(30%, -30%)',
          }}
        />

        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-6">
            <div
              className="flex items-center justify-center rounded-xl"
              style={{ width: 44, height: 44, background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.25)' }}
            >
              <Target size={20} style={{ color: '#3B82F6' }} />
            </div>
            <div>
              <h2 className="font-semibold text-base" style={{ color: '#F9FAFB' }}>
                Launch Intelligence Scan
              </h2>
              <p className="text-xs" style={{ color: '#6B7280' }}>
                Agentic AI selects tools dynamically based on live findings
              </p>
            </div>
          </div>

          {/* Scan type toggle */}
          <div className="flex gap-2 mb-5">
            {([
              { type: 'passive' as ScanType, label: 'Quick Recon', icon: Globe, desc: 'Passive only · No active traffic', proOnly: false },
              { type: 'active'  as ScanType, label: 'Full Pentest', icon: Zap,  desc: 'Pro · Active scanning',           proOnly: true  },
            ]).map(({ type, label, icon: Icon, desc, proOnly }) => {
              const isSelected = scanType === type
              const locked = proOnly && !isPro
              return (
                <button
                  key={type}
                  onClick={() => !locked && setScanType(type)}
                  className="flex items-center gap-2.5 px-4 py-2.5 rounded-lg transition-all text-left"
                  style={{
                    background: isSelected ? 'rgba(59,130,246,0.12)' : 'rgba(17,24,39,0.6)',
                    border: isSelected ? '1px solid rgba(59,130,246,0.4)' : '1px solid #1F2937',
                    cursor: locked ? 'not-allowed' : 'pointer',
                    opacity: locked ? 0.7 : 1,
                  }}
                >
                  {locked
                    ? <Lock size={14} style={{ color: '#6B7280' }} />
                    : <Icon size={14} style={{ color: isSelected ? '#3B82F6' : '#6B7280' }} />
                  }
                  <div>
                    <div className="text-sm font-medium" style={{ color: isSelected ? '#F9FAFB' : '#9CA3AF' }}>
                      {label}
                    </div>
                    <div className="text-xs" style={{ color: '#4B5563' }}>{desc}</div>
                  </div>
                  {locked && (
                    <span
                      className="ml-auto text-xs px-1.5 py-0.5 rounded font-semibold"
                      style={{ background: 'rgba(234,179,8,0.15)', color: '#EAB308', border: '1px solid rgba(234,179,8,0.25)' }}
                    >
                      PRO
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {/* Domain input row */}
          <div className="flex gap-3 items-start">
            <div className="flex-1 relative">
              <Globe
                size={14}
                className="absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: '#4B5563' }}
              />
              <input
                ref={inputRef}
                type="text"
                className="sx-input pl-9"
                placeholder="target-domain.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isLaunching}
                spellCheck={false}
                autoComplete="off"
              />
            </div>
            <button
              className="sx-btn shrink-0"
              onClick={handleLaunch}
              disabled={isLaunching || !domain.trim()}
              style={{ height: 44, minWidth: 140 }}
            >
              {isLaunching ? (
                <>
                  <span className="spin">⊙</span>
                  Launching…
                </>
              ) : (
                <>
                  <Play size={14} />
                  Launch Scan
                </>
              )}
            </button>
          </div>

          {/* Auth confirmation for active scans */}
          {scanType === 'active' && (
            <div className="flex items-center gap-2 mt-3">
              <input
                type="checkbox"
                id="auth-confirm"
                checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
                className="w-4 h-4 cursor-pointer"
                style={{ accentColor: '#3B82F6' }}
              />
              <label htmlFor="auth-confirm" className="text-xs cursor-pointer" style={{ color: '#9CA3AF' }}>
                I confirm I have written authorization to perform active scanning on this target
              </label>
            </div>
          )}

          {/* Error */}
          {error && (
            <div
              className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
              style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#FCA5A5' }}
            >
              <AlertTriangle size={13} />
              {error}
            </div>
          )}
        </div>
      </div>

      {/* ── Recent scans table ── */}
      <div className="glass" style={{ padding: '24px 28px' }}>
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Activity size={15} style={{ color: '#3B82F6' }} />
            <h3 className="font-semibold text-sm" style={{ color: '#F9FAFB' }}>Recent Scans</h3>
          </div>
          <button
            className="text-xs hover:underline"
            style={{ color: '#3B82F6' }}
            onClick={() => navigate('/scans')}
          >
            View all <ChevronRight size={11} className="inline" />
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="sx-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Target</th>
                <th>Type</th>
                <th>Risk Score</th>
                <th>Progress</th>
                <th>Started</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-12" style={{ color: '#4B5563' }}>
                    No scans yet — launch your first scan above
                  </td>
                </tr>
              )}
              {scans.map((scan) => {
                const risk = DEMO_RISK[scan.id] ?? 0
                const riskCol = risk ? riskColor(risk) : '#4B5563'
                return (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)}>
                    <td>
                      <div className="flex items-center gap-2">
                        <div
                          className={scan.status === 'running' ? 'pulse-dot' : ''}
                          style={{
                            width: 7, height: 7, borderRadius: '50%',
                            background: scan.status === 'complete' ? '#22C55E'
                              : scan.status === 'running' ? '#3B82F6'
                              : scan.status === 'failed' ? '#EF4444'
                              : '#6B7280',
                          }}
                        />
                        <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                      </div>
                    </td>
                    <td>
                      <span className="font-mono text-sm font-medium" style={{ color: '#E5E7EB' }}>
                        {scan.domain}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs" style={{ color: '#9CA3AF' }}>
                        {scan.scan_type === 'passive' ? 'Quick Recon'
                          : scan.scan_type === 'active' ? 'Active Pentest'
                          : 'Full Pentest'}
                      </span>
                    </td>
                    <td>
                      {risk > 0 ? (
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-sm" style={{ color: riskCol }}>{risk}</span>
                          <div className="progress-bar" style={{ width: 60 }}>
                            <div className="progress-fill" style={{ width: `${risk}%`, background: riskCol }} />
                          </div>
                        </div>
                      ) : (
                        <span style={{ color: '#4B5563' }}>—</span>
                      )}
                    </td>
                    <td>
                      {scan.status === 'running' ? (
                        <div className="flex items-center gap-2">
                          <div className="progress-bar flex-1" style={{ minWidth: 80 }}>
                            <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                          </div>
                          <span className="text-xs font-mono" style={{ color: '#6B7280' }}>{scan.progress}%</span>
                        </div>
                      ) : (
                        <span className="text-xs" style={{ color: '#4B5563' }}>
                          {scan.status === 'complete' ? '100%' : '—'}
                        </span>
                      )}
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <Clock size={11} style={{ color: '#4B5563' }} />
                        <span className="text-xs" style={{ color: '#6B7280' }}>
                          {formatRelativeTime(scan.created_at)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <button
                        className="flex items-center gap-1 text-xs hover:underline"
                        style={{ color: '#3B82F6' }}
                        onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`) }}
                      >
                        View <ChevronRight size={11} />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Feature callouts ── */}
      <div className="grid grid-cols-3 gap-4 mt-6">
        {[
          {
            icon: TrendingUp,
            color: '#3B82F6',
            title: 'Adaptive Tool Selection',
            desc: 'LLM orchestrator chooses tools based on live findings, not static pipelines.',
          },
          {
            icon: ShieldCheck,
            color: '#22C55E',
            title: 'OWASP Top 10 Coverage',
            desc: 'Every scan maps findings to all 10 OWASP categories with gap analysis.',
          },
          {
            icon: Activity,
            color: '#8B5CF6',
            title: 'Real-Time Intelligence',
            desc: 'Findings stream to your browser via WebSocket as each tool completes.',
          },
        ].map(({ icon: Icon, color, title, desc }) => (
          <div
            key={title}
            className="glass-sm px-4 py-4"
            style={{ transition: 'border-color 0.2s' }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Icon size={14} style={{ color }} />
              <span className="text-xs font-semibold" style={{ color: '#E5E7EB' }}>{title}</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: '#6B7280' }}>{desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
