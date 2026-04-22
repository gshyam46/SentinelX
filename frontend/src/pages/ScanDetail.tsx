import React, { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer,
} from 'recharts'
import {
  ArrowLeft, Globe, Clock, RefreshCw, Lock, ChevronDown,
  ChevronRight, AlertTriangle, Shield, Zap, Brain,
  Link2, TrendingUp, CheckCircle2,
} from 'lucide-react'
import { api, type ScanResultResponse, type Finding, type AnalysisReport } from '@/lib/api'
import { useScanLive } from '@/lib/api'
import { severityColor, riskColor, formatRelativeTime } from '@/lib/utils'
import RiskGauge from '@/components/RiskGauge'
import LiveAgentFeed from '@/components/LiveAgentFeed'
import FindingRow from '@/components/FindingRow'

// ── OWASP radar data helpers ──────────────────────────────────────────
const OWASP_CATS = ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10']
const OWASP_SHORT: Record<string,string> = {
  A01:'Access Ctrl', A02:'Crypto', A03:'Injection', A04:'Design',
  A05:'Misconfig', A06:'Components', A07:'Auth', A08:'Integrity',
  A09:'Logging', A10:'SSRF',
}

function buildRadarData(coverage: Record<string,string>) {
  return OWASP_CATS.map(cat => ({
    cat: OWASP_SHORT[cat] ?? cat,
    value: coverage[cat] === 'covered' ? 3 : coverage[cat] === 'partial' ? 1.5 : 0,
    fullMark: 3,
  }))
}

// ── Attack chain card ─────────────────────────────────────────────────
function AttackChainCard({ chain, idx }: { chain: { name:string; steps:string[]; impact:string }; idx: number }) {
  const [open, setOpen] = useState(false)
  const impactColor = chain.impact === 'high' ? '#EF4444' : chain.impact === 'medium' ? '#F97316' : '#EAB308'
  return (
    <div className="rounded-lg overflow-hidden" style={{ border: '1px solid #1F2937' }}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-white/5"
        onClick={() => setOpen(!open)}
      >
        <div
          className="flex items-center justify-center rounded font-mono text-xs font-bold"
          style={{ width:24, height:24, background:'rgba(239,68,68,0.12)', color:'#EF4444' }}
        >{idx+1}</div>
        <span className="flex-1 text-sm font-medium" style={{ color:'#E5E7EB' }}>{chain.name}</span>
        <span className="text-xs font-semibold" style={{ color: impactColor }}>{chain.impact.toUpperCase()}</span>
        {open ? <ChevronDown size={13} style={{color:'#6B7280'}} /> : <ChevronRight size={13} style={{color:'#6B7280'}} />}
      </button>
      {open && (
        <div className="px-4 pb-3 space-y-1.5" style={{ borderTop:'1px solid #1F2937', background:'rgba(0,0,0,0.2)' }}>
          {chain.steps.map((step,i) => (
            <div key={i} className="flex items-start gap-2 pt-2">
              <div className="flex items-center justify-center rounded-full font-mono text-xs shrink-0 mt-0.5"
                style={{ width:18, height:18, background:'rgba(59,130,246,0.12)', color:'#60A5FA', fontSize:10 }}>
                {i+1}
              </div>
              <span className="text-xs leading-relaxed" style={{ color:'#9CA3AF' }}>{step}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Remediation priority card ─────────────────────────────────────────
function RemCard({ item }: { item:{priority:number;finding:string;action:string;effort:string} }) {
  const effortColor = item.effort==='low' ? '#22C55E' : item.effort==='medium' ? '#EAB308' : '#EF4444'
  return (
    <div className="flex gap-3 py-2.5" style={{ borderBottom:'1px solid rgba(31,41,55,0.5)' }}>
      <div className="flex items-center justify-center rounded font-mono text-xs font-bold shrink-0"
        style={{ width:22, height:22, background:'rgba(59,130,246,0.1)', color:'#60A5FA', marginTop:2 }}>
        {item.priority}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold mb-0.5 truncate" style={{ color:'#E5E7EB' }}>{item.finding}</p>
        <p className="text-xs leading-relaxed" style={{ color:'#9CA3AF' }}>{item.action}</p>
      </div>
      <span className="text-xs font-semibold shrink-0 mt-1" style={{ color: effortColor }}>
        {item.effort}
      </span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────
export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()

  const [scan, setScan] = useState<ScanResultResponse | null>(null)
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [liveFindings, setLiveFindings] = useState<Finding[]>([])
  const [newFindingIds, setNewFindingIds] = useState<Set<number>>(new Set())
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'findings'|'chains'>('findings')
  const newFindingTimer = useRef<ReturnType<typeof setTimeout>|null>(null)

  // ── Initial load ───────────────────────────────────────────────────
  useEffect(() => {
    if (!scanId) return
    let alive = true
    const load = async () => {
      try {
        const data = await api.getScan(scanId)
        if (!alive) return
        setScan(data)
        setLiveFindings(data.results?.findings ?? [])
        setLoading(false)
        // Also try to fetch report
        try {
          const rep = await api.getScanReport(scanId)
          if (alive) setReport(rep)
        } catch { /* not ready yet */ }
      } catch {
        setLoading(false)
      }
    }
    load()
    return () => { alive = false }
  }, [scanId])

  // ── Poll while running ─────────────────────────────────────────────
  useEffect(() => {
    if (!scanId) return
    if (scan?.status === 'complete' || scan?.status === 'failed') return
    const id = setInterval(async () => {
      try {
        const data = await api.getScan(scanId)
        setScan(data)
        const serverFindings = data.results?.findings ?? []
        if (serverFindings.length > liveFindings.length) {
          setLiveFindings(serverFindings)
        }
      } catch { /* ignore */ }
    }, 5000)
    return () => clearInterval(id)
  }, [scanId, scan?.status, liveFindings.length])

  // ── WebSocket new findings ─────────────────────────────────────────
  const handleNewFinding = (f: Finding) => {
    setLiveFindings(prev => {
      const idx = prev.length
      const next = [...prev, f]
      setNewFindingIds(s => new Set(s).add(idx))
      if (newFindingTimer.current) clearTimeout(newFindingTimer.current)
      newFindingTimer.current = setTimeout(
        () => setNewFindingIds(new Set()),
        2000
      )
      return next
    })
  }

  const handleScanComplete = async () => {
    if (!scanId) return
    try {
      const [data, rep] = await Promise.all([
        api.getScan(scanId),
        api.getScanReport(scanId).catch(() => null),
      ])
      setScan(data)
      setLiveFindings(data.results?.findings ?? [])
      if (rep) setReport(rep)
    } catch { /* ignore */ }
  }

  const isRunning = scan?.status === 'running' || scan?.status === 'pending'
  const findings = liveFindings
  const isFreeTier = !!(scan?.results?.gated)
  const hiddenCount = scan?.results?.hidden_findings_count ?? 0
  const riskScore = report?.risk_score ?? scan?.risk_score ?? 0

  // Severity summary
  const sevCounts = { critical:0, high:0, medium:0, low:0, info:0 }
  findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++ })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ color:'#4B5563' }}>
        <RefreshCw size={22} className="spin" />
        <span className="ml-3 text-sm">Loading scan…</span>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-4" style={{ color:'#4B5563' }}>
        <AlertTriangle size={32} />
        <p className="text-sm">Scan not found</p>
        <button className="sx-btn sx-btn-ghost text-sm" onClick={() => navigate('/')}>
          <ArrowLeft size={13} /> Go back
        </button>
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-screen" style={{ background:'#0A0D14' }}>

      {/* ── Top bar ─────────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-4 px-6 py-3 shrink-0"
        style={{ borderBottom:'1px solid #1F2937', background:'rgba(10,13,20,0.9)', backdropFilter:'blur(16px)', position:'sticky', top:0, zIndex:30 }}
      >
        <button
          className="flex items-center gap-1.5 text-xs hover:text-white transition-colors"
          style={{ color:'#6B7280' }}
          onClick={() => navigate('/')}
        >
          <ArrowLeft size={13} /> Back
        </button>

        <div style={{ width:1, height:20, background:'#1F2937' }} />

        {/* Target */}
        <div className="flex items-center gap-2">
          <Globe size={14} style={{ color:'#3B82F6' }} />
          <span className="font-mono font-semibold text-sm" style={{ color:'#F9FAFB' }}>
            {scan.domain}
          </span>
        </div>

        {/* Scan type badge */}
        <span
          className="text-xs px-2 py-0.5 rounded font-semibold uppercase tracking-wider"
          style={{ background:'rgba(59,130,246,0.1)', color:'#60A5FA', border:'1px solid rgba(59,130,246,0.2)' }}
        >
          {scan.scan_type}
        </span>

        {/* Live indicator */}
        {isRunning && (
          <div className="flex items-center gap-1.5 ml-1">
            <div className="pulse-dot" style={{ width:7, height:7, borderRadius:'50%', background:'#3B82F6' }} />
            <span className="text-xs font-semibold" style={{ color:'#60A5FA' }}>LIVE</span>
          </div>
        )}

        <div className="flex-1" />

        {/* Status badge */}
        <span className={`badge badge-${scan.status}`}>{scan.status.toUpperCase()}</span>

        {/* Timestamps */}
        <div className="flex items-center gap-1.5">
          <Clock size={12} style={{ color:'#4B5563' }} />
          <span className="text-xs" style={{ color:'#6B7280' }}>
            {formatRelativeTime(scan.created_at)}
          </span>
        </div>
      </div>

      {/* ── Main split layout ────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0">

        {/* LEFT — 65%: Findings + agent feed */}
        <div className="flex flex-col" style={{ width:'65%', borderRight:'1px solid #1F2937' }}>

          {/* Risk summary strip */}
          <div
            className="flex items-center gap-6 px-6 py-3 shrink-0"
            style={{ borderBottom:'1px solid #1F2937', background:'rgba(0,0,0,0.2)' }}
          >
            {/* Severity chips */}
            {(['critical','high','medium','low','info'] as const).map(sev => (
              <div key={sev} className="flex items-center gap-1.5">
                <div style={{ width:8, height:8, borderRadius:'50%', background: severityColor(sev) }} />
                <span className="font-mono text-xs font-bold" style={{ color: severityColor(sev) }}>
                  {sevCounts[sev]}
                </span>
                <span className="text-xs capitalize" style={{ color:'#6B7280' }}>{sev}</span>
              </div>
            ))}
            <div className="flex-1" />
            <span className="text-xs" style={{ color:'#6B7280' }}>
              {findings.length} total{hiddenCount > 0 && ` · ${hiddenCount} locked`}
            </span>
          </div>

          {/* Agent feed (running only) */}
          {isRunning && scanId && (
            <div style={{ height:220, borderBottom:'1px solid #1F2937', flexShrink:0 }}>
              <LiveAgentFeed
                scanId={scanId}
                onNewFinding={handleNewFinding}
                onScanComplete={handleScanComplete}
              />
            </div>
          )}

          {/* Findings table header + tabs */}
          <div
            className="flex items-center gap-1 px-6 py-2 shrink-0"
            style={{ borderBottom:'1px solid #1F2937' }}
          >
            {(['findings','chains'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className="px-3 py-1.5 rounded text-xs font-semibold capitalize transition-colors"
                style={{
                  background: activeTab===tab ? 'rgba(59,130,246,0.12)' : 'transparent',
                  color: activeTab===tab ? '#3B82F6' : '#6B7280',
                  border: activeTab===tab ? '1px solid rgba(59,130,246,0.25)' : '1px solid transparent',
                }}
              >
                {tab === 'findings'
                  ? `Findings (${findings.length})`
                  : `Attack Chains (${report?.attack_chains?.length ?? 0})`}
              </button>
            ))}
          </div>

          {/* Scrollable body */}
          <div className="flex-1 overflow-y-auto">
            {activeTab === 'findings' && (
              <>
                <table className="sx-table" style={{ tableLayout:'fixed', width:'100%' }}>
                  <colgroup>
                    <col style={{ width:90 }} />
                    <col />
                    <col style={{ width:100 }} />
                    <col style={{ width:110 }} />
                    <col style={{ width:160 }} />
                    <col style={{ width:40 }} />
                  </colgroup>
                  <thead style={{ position:'sticky', top:0, background:'#0A0D14', zIndex:10 }}>
                    <tr>
                      <th>Severity</th>
                      <th>Title</th>
                      <th>OWASP</th>
                      <th>Tool</th>
                      <th>Target</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.length === 0 && (
                      <tr>
                        <td colSpan={6} className="text-center py-16" style={{ color:'#4B5563' }}>
                          {isRunning
                            ? 'Waiting for first finding…'
                            : 'No findings recorded'}
                        </td>
                      </tr>
                    )}
                    {findings.map((f,i) => (
                      <FindingRow
                        key={i}
                        finding={f}
                        index={i}
                        gated={isFreeTier && i >= 5}
                        isNew={newFindingIds.has(i)}
                      />
                    ))}
                  </tbody>
                </table>

                {/* Gated CTA */}
                {isFreeTier && hiddenCount > 0 && (
                  <div
                    className="mx-4 my-4 flex items-center justify-between gap-4 px-5 py-4 rounded-xl"
                    style={{ background:'rgba(59,130,246,0.06)', border:'1px solid rgba(59,130,246,0.2)' }}
                  >
                    <div className="flex items-center gap-3">
                      <Lock size={16} style={{ color:'#3B82F6' }} />
                      <div>
                        <p className="text-sm font-semibold" style={{ color:'#E5E7EB' }}>
                          {hiddenCount} more findings locked
                        </p>
                        <p className="text-xs" style={{ color:'#6B7280' }}>
                          {scan.results?.upgrade_message}
                        </p>
                      </div>
                    </div>
                    <button className="sx-btn text-sm shrink-0" style={{ padding:'8px 18px' }}>
                      Upgrade to Pro
                    </button>
                  </div>
                )}
              </>
            )}

            {activeTab === 'chains' && (
              <div className="p-5 space-y-3">
                {(!report?.attack_chains || report.attack_chains.length === 0) ? (
                  <div className="flex flex-col items-center justify-center py-16 gap-3" style={{ color:'#4B5563' }}>
                    <Link2 size={28} />
                    <p className="text-sm">
                      {isRunning ? 'Attack chains will appear after scan completes' : 'No attack chains identified'}
                    </p>
                  </div>
                ) : (
                  report.attack_chains.map((chain,i) => (
                    <AttackChainCard key={i} chain={chain} idx={i} />
                  ))
                )}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT — 35%: AI Insights panel */}
        <div
          className="flex flex-col overflow-y-auto"
          style={{ width:'35%', background:'rgba(0,0,0,0.2)' }}
        >
          {/* Risk gauge */}
          <div
            className="flex flex-col items-center py-6 shrink-0"
            style={{ borderBottom:'1px solid #1F2937' }}
          >
            <p className="text-xs font-semibold uppercase tracking-widest mb-4" style={{ color:'#4B5563' }}>
              Risk Score
            </p>
            <RiskGauge score={riskScore} size={150} />

            {/* Budget indicator */}
            {isRunning && (
              <div
                className="mt-4 flex items-center gap-2 px-3 py-1.5 rounded-lg"
                style={{ background:'rgba(59,130,246,0.08)', border:'1px solid rgba(59,130,246,0.15)' }}
              >
                <Zap size={12} style={{ color:'#60A5FA' }} />
                <span className="text-xs font-mono" style={{ color:'#60A5FA' }}>
                  {scan.current_step ?? 'Scanning…'}
                </span>
              </div>
            )}
          </div>

          {/* Executive Summary */}
          <div className="px-5 py-4 shrink-0" style={{ borderBottom:'1px solid #1F2937' }}>
            <div className="flex items-center gap-2 mb-3">
              <Brain size={13} style={{ color:'#8B5CF6' }} />
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#6B7280' }}>
                Executive Summary
              </span>
            </div>
            {report?.executive_summary ? (
              <p className="text-sm leading-relaxed" style={{ color:'#D1D5DB' }}>
                {report.executive_summary}
              </p>
            ) : (
              <p className="text-xs italic" style={{ color:'#4B5563' }}>
                {isRunning ? 'Analysis will appear after scan completes…' : 'No AI report available'}
              </p>
            )}
          </div>

          {/* Top 3 critical risks */}
          {report?.critical_findings && report.critical_findings.length > 0 && (
            <div className="px-5 py-4 shrink-0" style={{ borderBottom:'1px solid #1F2937' }}>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={13} style={{ color:'#EF4444' }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#6B7280' }}>
                  Top Critical Risks
                </span>
              </div>
              <div className="space-y-2">
                {report.critical_findings.slice(0,3).map((title,i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-3 py-2 rounded-lg"
                    style={{ background:'rgba(239,68,68,0.06)', border:'1px solid rgba(239,68,68,0.12)' }}
                  >
                    <div style={{ width:6, height:6, borderRadius:'50%', background:'#EF4444', flexShrink:0 }} />
                    <span className="text-xs" style={{ color:'#FCA5A5' }}>{title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* OWASP Radar */}
          <div className="px-5 py-4 shrink-0" style={{ borderBottom:'1px solid #1F2937' }}>
            <div className="flex items-center gap-2 mb-3">
              <Shield size={13} style={{ color:'#3B82F6' }} />
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#6B7280' }}>
                OWASP Coverage
              </span>
            </div>
            {report?.owasp_coverage ? (
              <>
                <ResponsiveContainer width="100%" height={200}>
                  <RadarChart data={buildRadarData(report.owasp_coverage)} margin={{ top:0, right:20, bottom:0, left:20 }}>
                    <PolarGrid stroke="#1F2937" />
                    <PolarAngleAxis
                      dataKey="cat"
                      tick={{ fill:'#4B5563', fontSize:9, fontFamily:'JetBrains Mono' }}
                    />
                    <Radar
                      name="Coverage"
                      dataKey="value"
                      stroke="#3B82F6"
                      fill="#3B82F6"
                      fillOpacity={0.15}
                      strokeWidth={1.5}
                    />
                  </RadarChart>
                </ResponsiveContainer>
                {/* Coverage legend */}
                <div className="grid grid-cols-2 gap-1 mt-2">
                  {OWASP_CATS.slice(0,6).map(cat => {
                    const val = report.owasp_coverage[cat] ?? 'missing'
                    const col = val==='covered' ? '#22C55E' : val==='partial' ? '#EAB308' : '#4B5563'
                    return (
                      <div key={cat} className="flex items-center gap-1.5">
                        <div style={{ width:6, height:6, borderRadius:'50%', background:col, flexShrink:0 }} />
                        <span className="font-mono text-xs" style={{ color:'#6B7280' }}>{cat}</span>
                        <span className="text-xs capitalize" style={{ color:col, fontSize:10 }}>{val}</span>
                      </div>
                    )
                  })}
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center py-8 gap-2" style={{ color:'#374151' }}>
                <Shield size={24} />
                <p className="text-xs">Coverage map available after analysis</p>
              </div>
            )}
          </div>

          {/* Remediation priorities */}
          {report?.remediation_priorities && report.remediation_priorities.length > 0 && (
            <div className="px-5 py-4 shrink-0" style={{ borderBottom:'1px solid #1F2937' }}>
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp size={13} style={{ color:'#22C55E' }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#6B7280' }}>
                  Remediation Priorities
                </span>
              </div>
              <div>
                {report.remediation_priorities.slice(0,5).map((item,i) => (
                  <RemCard key={i} item={item} />
                ))}
              </div>
            </div>
          )}

          {/* Analyst confidence */}
          {report && (
            <div className="px-5 py-4 shrink-0">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 size={13} style={{ color:'#22C55E' }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#6B7280' }}>
                  Analyst Confidence
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1">
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width:'82%', background:'#22C55E' }} />
                  </div>
                </div>
                <span className="text-sm font-bold font-mono" style={{ color:'#22C55E' }}>82%</span>
              </div>
              {report.model_used && (
                <p className="text-xs mt-2 font-mono" style={{ color:'#4B5563' }}>
                  Model: {report.model_used}
                </p>
              )}
              {report.analyst_notes && (
                <p className="text-xs mt-2 leading-relaxed" style={{ color:'#6B7280' }}>
                  {report.analyst_notes}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
