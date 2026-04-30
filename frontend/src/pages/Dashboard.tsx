import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, AlertTriangle, ShieldCheck, Play, BarChart3,
  TrendingUp, Clock, ChevronRight, Plus, Globe,
} from 'lucide-react'
import { api, type ScanStatusResponse } from '../lib/api'
import { useAuth } from '../lib/auth'
import { riskColor, severityColor, COLOR } from '../lib/theme'
import { formatRelativeTime } from '../lib/utils'
import NewScanModal from '../components/NewScanModal'

// ── Helpers ───────────────────────────────────────────────────────────────

function RiskPill({ score }: { score: number }) {
  if (!score) return <span style={{ color: COLOR.text.muted }}>—</span>
  const c = riskColor(score)
  return (
    <span className="mono font-bold text-xs px-2 py-0.5 rounded-full" style={{ background: `${c}15`, color: c, border: `1px solid ${c}35` }}>
      {Math.round(score)}
    </span>
  )
}

function SevChips({ scan }: { scan: ScanStatusResponse }) {
  const pairs = [
    { n: scan.critical_count, c: COLOR.severity.critical, l: 'C' },
    { n: scan.high_count,     c: COLOR.severity.high,     l: 'H' },
    { n: scan.medium_count,   c: COLOR.severity.medium,   l: 'M' },
    { n: scan.low_count,      c: COLOR.severity.low,      l: 'L' },
  ]
  return (
    <div className="flex items-center gap-2">
      {pairs.map(({ n, c, l }) => (
        <span key={l} className="mono text-xs">
          <span style={{ color: c, fontWeight: 700 }}>{n}</span>
          <span style={{ color: COLOR.text.muted }}>{l}</span>
        </span>
      ))}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  return (
    <div className="flex items-center gap-1.5">
      {status === 'running' && (
        <div className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.accent }} />
      )}
      <span className={`badge badge-${status}`}>{status}</span>
    </div>
  )
}

// ── Dashboard ─────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate  = useNavigate()
  const { user, isPro } = useAuth()
  const [showModal, setShowModal]   = useState(false)
  const [scans, setScans]           = useState<ScanStatusResponse[]>([])
  const [loading, setLoading]       = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())

  useEffect(() => {
    let alive = true
    const fetch = async () => {
      try {
        const d = await api.listScans(0, 50)
        if (alive) { setScans(d.scans); setLoading(false); setLastUpdated(new Date()) }
      } catch {
        if (alive) setLoading(false)
      }
    }
    fetch()
    const id = setInterval(fetch, 12_000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  const total    = scans.length
  const active   = scans.filter(s => s.status === 'running').length
  const critical = scans.reduce((a, s) => a + (s.critical_count ?? 0), 0)
  const complete = scans.filter(s => s.status === 'complete')
  const avgRisk  = complete.length > 0
    ? complete.reduce((a, s) => a + (s.risk_score ?? 0), 0) / complete.length
    : 0

  const STATS = [
    { label: 'Total Scans',      value: total,    icon: BarChart3,     color: COLOR.slate['300'], sub: `${complete.length} complete` },
    { label: 'Active',           value: active,   icon: Activity,      color: active > 0 ? COLOR.accent : COLOR.slate['300'], sub: active > 0 ? 'Scanning in progress' : 'No active scans' },
    { label: 'Critical Findings', value: critical, icon: AlertTriangle, color: critical > 0 ? COLOR.danger : COLOR.slate['300'], sub: critical > 0 ? 'Requires attention' : 'None detected' },
    { label: 'Avg Risk Score',   value: avgRisk > 0 ? Math.round(avgRisk) : '—', icon: TrendingUp, color: riskColor(avgRisk), sub: complete.length > 0 ? `across ${complete.length} scans` : 'No completed scans' },
  ]

  return (
    <div style={{ minHeight: '100vh', background: COLOR.bg.base }}>

      {/* Header */}
      <div
        className="flex items-center justify-between px-7 py-4 sticky top-0 z-20 scanline"
        style={{ background: `${COLOR.bg.base}f0`, borderBottom: `1px solid ${COLOR.bg.border}`, backdropFilter: 'blur(16px)' }}
      >
        <div>
          <h1 className="font-bold text-lg" style={{ color: COLOR.text.primary }}>Security Overview</h1>
          <p className="text-xs" style={{ color: COLOR.text.muted }}>
            Last updated {formatRelativeTime(lastUpdated.toISOString())}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {user && (
            <>
              <span className="mono text-sm" style={{ color: COLOR.text.muted }}>{user.email}</span>
              <span
                className="text-xs px-2 py-0.5 rounded-full font-bold"
                style={{
                  background: isPro ? 'rgba(46,165,95,0.1)' : 'rgba(74,109,130,0.1)',
                  color: isPro ? COLOR.accent : COLOR.slate['300'],
                  border: `1px solid ${isPro ? 'rgba(46,165,95,0.25)' : COLOR.bg.border}`,
                }}
              >
                {isPro ? 'PRO' : 'FREE'}
              </span>
            </>
          )}
          <button className="btn-primary" style={{ padding: '7px 16px', fontSize: 13 }} onClick={() => setShowModal(true)}>
            <Plus size={13} /> New Scan
          </button>
        </div>
      </div>

      <div className="px-7 py-7" style={{ maxWidth: 1280 }}>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-7">
          {STATS.map(({ label, value, icon: Icon, color, sub }) => (
            <div
              key={label}
              className="card flex items-center gap-4 transition-all"
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = `${color}30` }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = COLOR.bg.border }}
            >
              <div className="flex items-center justify-center rounded-lg flex-shrink-0" style={{ width: 40, height: 40, background: `${color}12` }}>
                <Icon size={18} style={{ color }} />
              </div>
              <div>
                <div className="text-2xl font-bold mono" style={{ color }}>{value}</div>
                <div className="text-xs mt-0.5" style={{ color: COLOR.text.muted }}>{label}</div>
                <div className="text-xs" style={{ color: COLOR.text.muted, opacity: 0.7 }}>{sub}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Scans table */}
        <div className="card" style={{ padding: '20px 24px' }}>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2">
              <Globe size={14} style={{ color: COLOR.accent }} />
              <h3 className="font-semibold text-sm" style={{ color: COLOR.text.primary }}>Assessments</h3>
            </div>
            <button className="btn-ghost text-xs" style={{ padding: '5px 12px' }} onClick={() => setShowModal(true)}>
              <Plus size={11} /> New Scan
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="sx-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Mode</th>
                  <th>Risk</th>
                  <th>C H M L</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={8} className="text-center py-10" style={{ color: COLOR.text.muted }}>
                      <span className="spin" style={{ marginRight: 8 }}>⊙</span>Loading scans…
                    </td>
                  </tr>
                )}
                {!loading && scans.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center py-16" style={{ color: COLOR.text.muted }}>
                      <div className="flex flex-col items-center gap-3">
                        <ShieldCheck size={28} style={{ opacity: 0.3 }} />
                        <p className="font-medium" style={{ color: COLOR.text.secondary }}>No scans yet</p>
                        <p className="text-xs">Start your first security assessment.</p>
                        <button className="btn-primary mt-1" style={{ padding: '7px 18px', fontSize: 13 }} onClick={() => setShowModal(true)}>
                          <Play size={12} /> Launch Scan
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
                {scans.map((scan) => (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)}>
                    <td>
                      <span className="mono font-medium text-sm" style={{ color: COLOR.text.primary }}>{scan.domain}</span>
                    </td>
                    <td>
                      <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(74,109,130,0.1)', color: COLOR.slate['300'], border: `1px solid ${COLOR.slate['600']}` }}>
                        {scan.scan_type}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs" style={{ color: COLOR.text.muted }}>{scan.scan_mode ?? '—'}</span>
                    </td>
                    <td><RiskPill score={scan.risk_score} /></td>
                    <td><SevChips scan={scan} /></td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <Clock size={11} style={{ color: COLOR.text.muted }} />
                        <span className="text-xs" style={{ color: COLOR.text.muted }}>{formatRelativeTime(scan.created_at)}</span>
                      </div>
                    </td>
                    <td>
                      <button
                        className="flex items-center gap-1 text-xs hover:underline"
                        style={{ color: COLOR.accent, background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`) }}
                      >
                        View <ChevronRight size={10} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

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
