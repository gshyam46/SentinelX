import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, AlertTriangle, ShieldCheck, Play,
  Zap, Lock, Globe, Clock, BarChart3, TrendingUp,
  X, Plus, ChevronRight,
} from 'lucide-react'
import { api, type ScanStatusResponse, type ScanType } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { riskColor, formatRelativeTime } from '@/lib/utils'
import { ACCENT, SEVERITY_COLOR, BG, DANGER, WARN } from '@/lib/theme'

// ── New Scan Modal ─────────────────────────────────────────────────────────────

interface NewScanModalProps {
  onClose: () => void
  onLaunched: (scanId: string) => void
  isPro: boolean
}

function NewScanModal({ onClose, onLaunched, isPro }: NewScanModalProps) {
  const [domain, setDomain] = useState('')
  const [scanType, setScanType] = useState<ScanType>('passive')
  const [scanMode, setScanMode] = useState<'deterministic' | 'adaptive'>('deterministic')
  const [authConfirmed, setAuthConfirmed] = useState(false)
  const [isLaunching, setIsLaunching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  async function handleLaunch() {
    if (!domain.trim()) { setError('Enter a target domain'); return }
    if (scanType !== 'passive' && !authConfirmed) {
      setError('You must confirm authorization to perform active scanning')
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
      })
      onLaunched(scan.id)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Failed to launch scan'
      setError(msg)
      setIsLaunching(false)
    }
  }

  const SCAN_TYPES: Array<{ type: ScanType; label: string; desc: string; icon: React.ElementType; proOnly: boolean }> = [
    { type: 'passive', label: 'Quick Recon',   desc: 'Passive only — no active traffic',  icon: Globe, proOnly: false },
    { type: 'active',  label: 'Active Pentest', desc: 'Active scanning with AI selection', icon: Zap,   proOnly: true  },
    { type: 'full',    label: 'Full Pentest',   desc: 'Passive + active combined',          icon: ShieldCheck, proOnly: true },
  ]

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        className="glass w-full relative"
        style={{ maxWidth: 540, padding: '32px 36px' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="font-bold text-lg" style={{ color: '#f9fafb' }}>New Security Assessment</h2>
            <p className="text-xs mt-0.5" style={{ color: '#6b7280' }}>
              AI orchestrator selects tools dynamically based on live findings
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            style={{ color: '#6b7280' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Target input */}
        <div className="mb-5">
          <label className="text-xs font-semibold uppercase tracking-wider mb-2 block" style={{ color: '#6b7280' }}>
            Target Domain
          </label>
          <div className="relative">
            <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#4b5563' }} />
            <input
              ref={inputRef}
              type="text"
              className="sx-input pl-9"
              placeholder="target-domain.com"
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
          <label className="text-xs font-semibold uppercase tracking-wider mb-2 block" style={{ color: '#6b7280' }}>
            Scan Type
          </label>
          <div className="grid grid-cols-3 gap-2">
            {SCAN_TYPES.map(({ type, label, desc, icon: Icon, proOnly }) => {
              const locked = proOnly && !isPro
              const selected = scanType === type
              return (
                <button
                  key={type}
                  onClick={() => !locked && setScanType(type)}
                  className="flex flex-col items-start gap-1 p-3 rounded-lg text-left transition-all"
                  style={{
                    background: selected ? `rgba(0,212,255,0.08)` : 'rgba(17,24,39,0.6)',
                    border: selected ? `1px solid rgba(0,212,255,0.35)` : `1px solid ${BG.border}`,
                    cursor: locked ? 'not-allowed' : 'pointer',
                    opacity: locked ? 0.6 : 1,
                  }}
                >
                  {locked
                    ? <Lock size={13} style={{ color: '#6b7280' }} />
                    : <Icon size={13} style={{ color: selected ? ACCENT : '#6b7280' }} />
                  }
                  <div className="text-xs font-semibold" style={{ color: selected ? '#f9fafb' : '#9ca3af' }}>
                    {label}
                  </div>
                  <div className="text-xs" style={{ color: '#4b5563', fontSize: 10 }}>{desc}</div>
                  {locked && (
                    <span className="text-xs px-1 py-0.5 rounded font-bold" style={{ background: `rgba(245,158,11,0.15)`, color: WARN }}>
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
            <label className="text-xs font-semibold uppercase tracking-wider mb-2 block" style={{ color: '#6b7280' }}>
              Execution Mode
            </label>
            <div className="flex gap-2">
              {(['deterministic', 'adaptive'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setScanMode(mode)}
                  className="px-3 py-2 rounded-lg text-xs font-semibold capitalize transition-all"
                  style={{
                    background: scanMode === mode ? 'rgba(139,92,246,0.12)' : 'rgba(17,24,39,0.6)',
                    border: scanMode === mode ? '1px solid rgba(139,92,246,0.4)' : `1px solid ${BG.border}`,
                    color: scanMode === mode ? '#a78bfa' : '#6b7280',
                    cursor: 'pointer',
                  }}
                >
                  {mode}
                </button>
              ))}
              <span className="self-center text-xs" style={{ color: '#4b5563' }}>
                {scanMode === 'adaptive' ? '— LLM picks tools dynamically' : '— fixed tool sequence'}
              </span>
            </div>
          </div>
        )}

        {/* Auth confirmation */}
        {scanType !== 'passive' && (
          <div className="flex items-start gap-2.5 mb-5 p-3 rounded-lg" style={{ background: 'rgba(255,59,92,0.06)', border: '1px solid rgba(255,59,92,0.2)' }}>
            <input
              type="checkbox"
              id="auth-confirm"
              checked={authConfirmed}
              onChange={(e) => setAuthConfirmed(e.target.checked)}
              className="mt-0.5 w-4 h-4 cursor-pointer"
              style={{ accentColor: ACCENT }}
            />
            <label htmlFor="auth-confirm" className="text-xs cursor-pointer leading-relaxed" style={{ color: '#fca5a5' }}>
              I confirm I have written authorization to perform active scanning on this target.
              Unauthorized scanning is illegal.
            </label>
          </div>
        )}

        {/* Error */}
        {error && (
          <div
            className="mb-4 flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
            style={{ background: 'rgba(255,59,92,0.08)', border: '1px solid rgba(255,59,92,0.2)', color: '#fca5a5' }}
          >
            <AlertTriangle size={13} />
            {error}
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button
            className="sx-btn flex-1 justify-center"
            onClick={handleLaunch}
            disabled={isLaunching || !domain.trim()}
          >
            {isLaunching ? <><span className="spin">⊙</span> Launching…</> : <><Play size={14} /> Launch Scan</>}
          </button>
          <button
            className="sx-btn sx-btn-ghost px-5"
            onClick={onClose}
            disabled={isLaunching}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Risk pill ─────────────────────────────────────────────────────────────────

function RiskPill({ score }: { score: number }) {
  if (!score) return <span style={{ color: '#374151' }}>—</span>
  const color = riskColor(score)
  return (
    <span
      className="font-mono font-bold text-xs px-2.5 py-1 rounded-full"
      style={{ background: `${color}18`, color, border: `1px solid ${color}40` }}
    >
      {Math.round(score)}
    </span>
  )
}

// ── Severity count display ────────────────────────────────────────────────────

function SevCounts({ scan }: { scan: ScanStatusResponse }) {
  const pairs = [
    { count: scan.critical_count, color: SEVERITY_COLOR.critical, letter: 'C' },
    { count: scan.high_count,     color: SEVERITY_COLOR.high,     letter: 'H' },
    { count: scan.medium_count,   color: SEVERITY_COLOR.medium,   letter: 'M' },
    { count: scan.low_count,      color: SEVERITY_COLOR.low,      letter: 'L' },
  ]
  return (
    <div className="flex items-center gap-2">
      {pairs.map(({ count, color, letter }) => (
        <span key={letter} className="font-mono text-xs">
          <span style={{ color, fontWeight: 700 }}>{count}</span>
          <span style={{ color: '#374151' }}>{letter}</span>
        </span>
      ))}
    </div>
  )
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate()
  const { user, isPro } = useAuth()
  const [showModal, setShowModal] = useState(false)
  const [scans, setScans] = useState<ScanStatusResponse[]>([])
  const [scansLoading, setScansLoading] = useState(true)

  useEffect(() => {
    let alive = true
    const fetchScans = async () => {
      try {
        const data = await api.listScans(0, 50)
        if (alive) { setScans(data.scans); setScansLoading(false) }
      } catch {
        if (alive) setScansLoading(false)
      }
    }
    fetchScans()
    const id = setInterval(fetchScans, 10_000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  const totalScans = scans.length
  const activeScans = scans.filter(s => s.status === 'running').length
  const criticalFindings = scans.reduce((acc, s) => acc + (s.critical_count ?? 0), 0)
  const completedScans = scans.filter(s => s.status === 'complete')
  const avgRisk = completedScans.length > 0
    ? completedScans.reduce((acc, s) => acc + (s.risk_score ?? 0), 0) / completedScans.length
    : 0

  const STATS = [
    {
      label: 'Total Scans',
      value: totalScans,
      icon: BarChart3,
      color: ACCENT,
      sub: activeScans > 0 ? `${activeScans} running now` : `${completedScans.length} complete`,
    },
    {
      label: 'Active',
      value: activeScans,
      icon: Activity,
      color: '#60a5fa',
      sub: activeScans > 0 ? 'Scanning in progress' : 'No active scans',
    },
    {
      label: 'Critical Findings',
      value: criticalFindings,
      icon: AlertTriangle,
      color: DANGER,
      sub: criticalFindings > 0 ? 'Requires immediate action' : 'None detected',
    },
    {
      label: 'Avg Risk Score',
      value: avgRisk > 0 ? Math.round(avgRisk) : '—',
      icon: TrendingUp,
      color: riskColor(avgRisk),
      sub: completedScans.length > 0 ? `across ${completedScans.length} scans` : 'No completed scans',
    },
  ]

  return (
    <div style={{ minHeight: '100vh', background: BG.base }}>
      {/* ── Top header bar ── */}
      <div
        className="flex items-center justify-between px-8 py-4 sticky top-0 z-20"
        style={{ background: 'rgba(10,14,26,0.95)', borderBottom: `1px solid ${BG.border}`, backdropFilter: 'blur(16px)' }}
      >
        <div className="flex items-center gap-3">
          <span className="font-bold text-lg tracking-wider" style={{ color: '#f9fafb' }}>
            SENTINEL<span style={{ color: ACCENT }}>X</span>
          </span>
          <span className="text-xs" style={{ color: '#374151' }}>Security Command Center</span>
        </div>
        <div className="flex items-center gap-3">
          {user && (
            <>
              <span className="font-mono text-sm" style={{ color: '#6b7280' }}>{user.email}</span>
              <span
                className="text-xs px-2 py-0.5 rounded font-bold"
                style={{
                  background: isPro ? 'rgba(0,212,255,0.1)' : 'rgba(107,114,128,0.1)',
                  color: isPro ? ACCENT : '#9ca3af',
                  border: `1px solid ${isPro ? 'rgba(0,212,255,0.25)' : 'rgba(107,114,128,0.25)'}`,
                }}
              >
                {isPro ? 'PRO' : 'FREE'}
              </span>
            </>
          )}
          <button
            className="sx-btn"
            style={{ padding: '8px 18px', fontSize: 13 }}
            onClick={() => setShowModal(true)}
          >
            <Plus size={14} />
            New Scan
          </button>
        </div>
      </div>

      <div className="px-8 py-8 max-w-7xl">
        {/* ── Stats row ── */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          {STATS.map(({ label, value, icon: Icon, color, sub }) => (
            <div
              key={label}
              className="glass flex items-center gap-4 px-5 py-4"
              style={{ transition: 'border-color 0.2s' }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = `${color}35`)}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = BG.border)}
            >
              <div
                className="flex items-center justify-center rounded-lg shrink-0"
                style={{ width: 40, height: 40, background: `${color}12` }}
              >
                <Icon size={18} style={{ color }} />
              </div>
              <div>
                <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
                <div className="text-xs mt-0.5" style={{ color: '#6b7280' }}>{label}</div>
                <div className="text-xs mt-0.5" style={{ color: '#374151' }}>{sub}</div>
              </div>
            </div>
          ))}
        </div>

        {/* ── Scans table ── */}
        <div className="glass" style={{ padding: '24px 28px' }}>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2">
              <Activity size={15} style={{ color: ACCENT }} />
              <h3 className="font-semibold text-sm" style={{ color: '#f9fafb' }}>Assessments</h3>
            </div>
            <button
              className="sx-btn sx-btn-ghost text-xs"
              style={{ padding: '6px 14px' }}
              onClick={() => setShowModal(true)}
            >
              <Plus size={12} /> New Scan
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="sx-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Mode</th>
                  <th>Risk Score</th>
                  <th>C / H / M / L</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scansLoading && (
                  <tr>
                    <td colSpan={8} className="text-center py-10" style={{ color: '#4b5563' }}>
                      <span className="spin" style={{ display: 'inline-block', marginRight: 8 }}>⊙</span>
                      Loading scans…
                    </td>
                  </tr>
                )}
                {!scansLoading && scans.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center py-16" style={{ color: '#4b5563' }}>
                      <div className="flex flex-col items-center gap-3">
                        <ShieldCheck size={28} style={{ opacity: 0.3 }} />
                        <div>
                          <p className="font-medium" style={{ color: '#6b7280' }}>No scans yet.</p>
                          <p className="text-xs mt-1">Start your first assessment.</p>
                        </div>
                        <button className="sx-btn mt-2" style={{ padding: '8px 20px', fontSize: 13 }} onClick={() => setShowModal(true)}>
                          <Play size={13} /> Launch Scan
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
                {scans.map((scan) => (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)}>
                    {/* Target */}
                    <td>
                      <span className="font-mono text-sm font-medium" style={{ color: '#e5e7eb' }}>
                        {scan.domain}
                      </span>
                    </td>

                    {/* Type */}
                    <td>
                      <span
                        className="text-xs px-2 py-0.5 rounded font-semibold uppercase tracking-wide"
                        style={{ background: 'rgba(0,212,255,0.06)', color: '#67e8f9', border: '1px solid rgba(0,212,255,0.15)' }}
                      >
                        {scan.scan_type}
                      </span>
                    </td>

                    {/* Mode */}
                    <td>
                      <span className="text-xs" style={{ color: '#6b7280' }}>
                        {scan.scan_mode ?? '—'}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td><RiskPill score={scan.risk_score} /></td>

                    {/* C/H/M/L */}
                    <td><SevCounts scan={scan} /></td>

                    {/* Status */}
                    <td>
                      <div className="flex items-center gap-2">
                        {scan.status === 'running' && (
                          <div className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: ACCENT }} />
                        )}
                        <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                      </div>
                    </td>

                    {/* Started */}
                    <td>
                      <div className="flex items-center gap-1.5">
                        <Clock size={11} style={{ color: '#4b5563' }} />
                        <span className="text-xs" style={{ color: '#6b7280' }}>
                          {formatRelativeTime(scan.created_at)}
                        </span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td>
                      <button
                        className="flex items-center gap-1 text-xs hover:underline"
                        style={{ color: ACCENT }}
                        onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`) }}
                      >
                        View <ChevronRight size={11} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── New Scan Modal ── */}
      {showModal && (
        <NewScanModal
          isPro={isPro}
          onClose={() => setShowModal(false)}
          onLaunched={(id) => navigate(`/scans/${id}`)}
        />
      )}
    </div>
  )
}
