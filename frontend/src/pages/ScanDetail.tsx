import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Globe, Clock, RefreshCw, Lock, AlertTriangle,
  Shield, Zap, Brain, TrendingUp, CheckCircle2, X,
  ChevronRight, Cpu, Activity, Wrench,
} from 'lucide-react'
import { api, useScanLive, type ScanResultResponse, type Finding, type AnalysisReport, type LiveEvent } from '../lib/api'
import { severityColor, riskColor, COLOR } from '../lib/theme'
import { formatRelativeTime } from '../lib/utils'
import RiskGauge from '../components/RiskGauge'
import FindingRow from '../components/FindingRow'
import FindingDrawer from '../components/FindingDrawer'
import ExecutionGraph from '../components/ExecutionGraph'

// ── OWASP ─────────────────────────────────────────────────────────────────

const OWASP_CATS = ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10']
const OWASP_NAMES: Record<string,string> = {
  A01:'Broken Access Control', A02:'Cryptographic Failures', A03:'Injection',
  A04:'Insecure Design', A05:'Security Misconfiguration', A06:'Vulnerable Components',
  A07:'Auth Failures', A08:'Data Integrity Failures', A09:'Logging Failures', A10:'SSRF',
}

// ── OWASP coverage bars ───────────────────────────────────────────────────

function OWASPBars({ coverage }: { coverage: Record<string,string> }) {
  return (
    <div className="space-y-3">
      {OWASP_CATS.map(cat => {
        const val = coverage[cat] ?? 'missing'
        const pct = val === 'covered' ? 100 : val === 'partial' ? 50 : 0
        const col = val === 'covered' ? COLOR.success : val === 'partial' ? COLOR.warn : COLOR.bg.border
        return (
          <div key={cat}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span className="mono text-xs font-bold" style={{ color: COLOR.text.secondary, minWidth: 28 }}>{cat}</span>
                <span className="text-xs" style={{ color: COLOR.text.muted }}>{OWASP_NAMES[cat]}</span>
              </div>
              <span className="text-xs font-semibold capitalize" style={{
                color: val === 'covered' ? COLOR.success : val === 'partial' ? COLOR.warn : COLOR.text.muted,
              }}>{val}</span>
            </div>
            <div className="progress-bar">
              <div style={{ height: '100%', borderRadius: 99, width: `${pct}%`, background: col, transition: 'width 0.6s ease' }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Attack chain card ─────────────────────────────────────────────────────

function AttackChainCard({ chain, idx }: { chain: { name: string; steps: string[]; impact: string }; idx: number }) {
  const impactColor = chain.impact === 'high' ? COLOR.danger : chain.impact === 'medium' ? COLOR.warn : COLOR.success
  return (
    <div className="rounded-lg p-4" style={{ border: `1px solid ${chain.impact === 'high' ? COLOR.danger + '30' : COLOR.bg.border}`, background: 'rgba(0,0,0,0.15)' }}>
      <div className="flex items-center gap-3 mb-3">
        <div className="flex items-center justify-center rounded mono text-xs font-bold" style={{ width: 22, height: 22, background: `${impactColor}15`, color: impactColor }}>
          {idx + 1}
        </div>
        <span className="font-semibold text-sm flex-1" style={{ color: COLOR.text.primary }}>{chain.name}</span>
        <span className="text-xs font-bold uppercase" style={{ color: impactColor }}>{chain.impact}</span>
      </div>
      <div className="flex items-center flex-wrap gap-1.5">
        {chain.steps.map((step, i) => (
          <React.Fragment key={i}>
            {i > 0 && <ChevronRight size={11} style={{ color: COLOR.accent, flexShrink: 0 }} />}
            <span className="text-xs px-2 py-1 rounded" style={{ background: COLOR.bg.surface, color: COLOR.text.secondary, border: `1px solid ${COLOR.bg.border}` }}>
              {step}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────

type TabId = 'findings' | 'intelligence' | 'graph'

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate   = useNavigate()

  const [scan, setScan]               = useState<ScanResultResponse | null>(null)
  const [report, setReport]           = useState<AnalysisReport | null>(null)
  const [liveFindings, setLiveFindings] = useState<Finding[]>([])
  const [newFindingIds, setNewIds]    = useState<Set<number>>(new Set())
  const [loading, setLoading]         = useState(true)
  const [activeTab, setActiveTab]     = useState<TabId>('findings')
  const [pdfBusy, setPdfBusy]         = useState(false)
  const [selected, setSelected]       = useState<Finding | null>(null)
  const newTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [liveNodes, setLiveNodes] = useState<Array<{ id: string; type: string; data: Record<string,unknown> }>>([])
  const [liveEdges, setLiveEdges] = useState<Array<{ id: string; source: string; target: string; relationship?: string }>>([])

  const toolStartTimes = useRef<Map<string,number>>(new Map())
  const [tick, setTick] = useState(0)

  // Initial load
  useEffect(() => {
    if (!scanId) return
    let alive = true
    ;(async () => {
      try {
        const d = await api.getScan(scanId)
        if (!alive) return
        setScan(d)
        setLiveFindings(d.results?.findings ?? [])
        setLoading(false)
        try {
          const r = await api.getScanReport(scanId)
          if (alive) setReport(r)
        } catch { /* not ready */ }
      } catch {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [scanId])

  // Poll while running
  useEffect(() => {
    if (!scanId) return
    if (scan?.status === 'complete' || scan?.status === 'failed') return
    const id = setInterval(async () => {
      try {
        const d = await api.getScan(scanId)
        setScan(d)
        const sf = d.results?.findings ?? []
        if (sf.length > liveFindings.length) setLiveFindings(sf)
      } catch { /* ignore */ }
    }, 5000)
    return () => clearInterval(id)
  }, [scanId, scan?.status, liveFindings.length])

  const handleNewFinding = useCallback((f: Finding) => {
    setLiveFindings(prev => {
      const idx = prev.length
      setNewIds(s => new Set(s).add(idx))
      if (newTimer.current) clearTimeout(newTimer.current)
      newTimer.current = setTimeout(() => setNewIds(new Set()), 2000)
      return [...prev, f]
    })
  }, [])

  const handleScanComplete = useCallback(async () => {
    if (!scanId) return
    try {
      const [d, r] = await Promise.all([api.getScan(scanId), api.getScanReport(scanId).catch(() => null)])
      setScan(d)
      setLiveFindings(d.results?.findings ?? [])
      if (r) setReport(r)
    } catch { /* ignore */ }
  }, [scanId])

  const handleLiveEvent = useCallback((event: LiveEvent) => {
    if (event.type === 'tool_started' && event.tool) {
      toolStartTimes.current.set(event.tool, Date.now())
      setLiveNodes(prev => {
        if (prev.find(n => n.id === `tool_${event.tool}`)) return prev
        return [...prev, { id: `tool_${event.tool}`, type: 'tool_execution', data: { tool_name: event.tool, status: 'running' } }]
      })
    }
    if (event.type === 'tool_complete' && event.tool) {
      setLiveNodes(prev => prev.map(n =>
        n.id === `tool_${event.tool}` ? { ...n, data: { ...n.data, status: 'complete' } } : n
      ))
    }
    if (event.type === 'finding' && event.finding) {
      handleNewFinding(event.finding)
      const f = event.finding
      const nid = `finding_${Date.now()}`
      setLiveNodes(prev => [...prev, { id: nid, type: 'finding', data: { title: f.title, severity: f.severity, known_exploited: f.known_exploited ?? false } }])
      if (event.tool) {
        setLiveEdges(prev => [...prev, { id: `edge_${nid}`, source: `tool_${event.tool}`, target: nid, relationship: 'triggered' }])
      }
    }
    if (event.type === 'report_ready' || event.type === 'stream_end') handleScanComplete()
  }, [handleNewFinding, handleScanComplete])

  const isRunning = scan?.status === 'running' || scan?.status === 'pending'

  const { toolsInProgress } = useScanLive(isRunning ? (scanId ?? null) : null, handleLiveEvent)

  useEffect(() => {
    if (!isRunning || toolsInProgress.size === 0) return
    const id = setInterval(() => setTick(n => n + 1), 1000)
    return () => clearInterval(id)
  }, [isRunning, toolsInProgress.size])
  void tick

  async function handlePdf() {
    if (!scanId || pdfBusy) return
    setPdfBusy(true)
    try {
      const blob = await api.downloadScanPdf(scanId)
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = `sentinelx-${scanId}.pdf`; a.click()
      URL.revokeObjectURL(url)
    } catch { /* fail silently */ }
    finally { setPdfBusy(false) }
  }

  const findings     = liveFindings
  const isFreeTier   = !!(scan?.results?.gated)
  const hiddenCount  = scan?.results?.hidden_findings_count ?? 0
  const riskScore    = report?.risk_score ?? scan?.risk_score ?? 0
  const kevCveIds    = new Set(scan?.kev_matches ?? [])
  const sevCounts    = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++ })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ color: COLOR.text.muted }}>
        <RefreshCw size={20} className="spin" />
        <span className="ml-3 text-sm">Loading scan…</span>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-4" style={{ color: COLOR.text.muted }}>
        <AlertTriangle size={30} />
        <p className="text-sm">Scan not found</p>
        <button className="btn-ghost text-sm" onClick={() => navigate('/')}>
          <ArrowLeft size={12} /> Go back
        </button>
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-screen" style={{ background: COLOR.bg.base }}>

      {/* Top bar */}
      <div
        className="flex items-center gap-4 px-5 py-3 sticky top-0 z-30 shrink-0"
        style={{ borderBottom: `1px solid ${COLOR.bg.border}`, background: `${COLOR.bg.base}f0`, backdropFilter: 'blur(16px)' }}
      >
        <button
          className="flex items-center gap-1 text-xs transition-colors"
          style={{ color: COLOR.text.muted, background: 'none', border: 'none', cursor: 'pointer' }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = COLOR.text.primary }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = COLOR.text.muted }}
          onClick={() => navigate('/')}
        >
          <ArrowLeft size={12} /> Back
        </button>

        <div style={{ width: 1, height: 18, background: COLOR.bg.border }} />

        <div className="flex items-center gap-2">
          <Globe size={13} style={{ color: COLOR.accent }} />
          <span className="mono font-semibold text-sm" style={{ color: COLOR.text.primary }}>{scan.domain}</span>
        </div>

        <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(46,165,95,0.08)', color: COLOR.accent, border: '1px solid rgba(46,165,95,0.2)' }}>
          {scan.scan_type}
        </span>
        {scan.scan_mode && (
          <span className="text-xs px-2 py-0.5 rounded" style={{ background: COLOR.bg.surface, color: COLOR.text.muted, border: `1px solid ${COLOR.bg.border}` }}>
            {scan.scan_mode}
          </span>
        )}

        {isRunning && (
          <div className="flex items-center gap-1.5">
            <div className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: COLOR.accent }} />
            <span className="text-xs font-semibold" style={{ color: COLOR.accent }}>LIVE</span>
          </div>
        )}

        <div className="flex-1" />

        {/* Risk gauge */}
        <RiskGauge score={riskScore} size={56} />

        {/* Actions */}
        {scan.status === 'complete' && (
          <>
            <button
              onClick={handlePdf}
              disabled={pdfBusy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all"
              style={{ background: 'rgba(46,165,95,0.07)', border: '1px solid rgba(46,165,95,0.2)', color: COLOR.success, cursor: pdfBusy ? 'not-allowed' : 'pointer' }}
            >
              {pdfBusy ? <RefreshCw size={11} className="spin" /> : <TrendingUp size={11} />}
              {pdfBusy ? 'Generating…' : 'PDF Report'}
            </button>
            <button
              onClick={() => navigate(`/scans/${scanId}/llm-security`)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-all"
              style={{ background: 'rgba(74,109,130,0.08)', border: `1px solid ${COLOR.slate['600']}`, color: COLOR.slate['200'], cursor: 'pointer' }}
            >
              <Brain size={11} /> LLM Audit
            </button>
          </>
        )}

        <span className={`badge badge-${scan.status}`}>{scan.status.toUpperCase()}</span>
        <div className="flex items-center gap-1">
          <Clock size={11} style={{ color: COLOR.text.muted }} />
          <span className="text-xs" style={{ color: COLOR.text.muted }}>{formatRelativeTime(scan.created_at)}</span>
        </div>
      </div>

      {/* Live tool strip */}
      {isRunning && (
        <div className="flex items-center gap-4 px-5 py-2 shrink-0" style={{ borderBottom: `1px solid ${COLOR.bg.border}`, background: 'rgba(46,165,95,0.025)' }}>
          <div className="flex items-center gap-1.5">
            <Cpu size={11} style={{ color: COLOR.accent }} />
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: COLOR.accent }}>Scanning</span>
          </div>
          <div className="flex items-center gap-4 flex-1 overflow-x-auto">
            {Array.from(toolsInProgress).map(tool => {
              const elapsed = toolStartTimes.current.has(tool)
                ? Math.floor((Date.now() - toolStartTimes.current.get(tool)!) / 1000) : 0
              return (
                <div key={tool} className="flex items-center gap-1.5 shrink-0">
                  <div className="pulse-dot" style={{ width: 5, height: 5, borderRadius: '50%', background: COLOR.accent }} />
                  <span className="mono text-xs font-semibold" style={{ color: COLOR.slate['200'] }}>{tool}</span>
                  <span className="mono text-xs" style={{ color: COLOR.text.muted }}>{elapsed}s</span>
                </div>
              )
            })}
            {toolsInProgress.size === 0 && (
              <span className="text-xs" style={{ color: COLOR.text.muted }}>{scan.current_step ?? 'Initializing…'}</span>
            )}
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {(['critical','high','medium','low'] as const).map(sev => (
              <span key={sev} className="mono text-xs">
                <span style={{ color: severityColor(sev), fontWeight: 700 }}>{sevCounts[sev]}</span>
                <span style={{ color: COLOR.text.muted }}>{sev[0].toUpperCase()}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Severity summary */}
      <div className="flex items-center gap-5 px-5 py-2 shrink-0" style={{ borderBottom: `1px solid ${COLOR.bg.border}`, background: 'rgba(0,0,0,0.1)' }}>
        {(['critical','high','medium','low','info'] as const).map(sev => (
          <div key={sev} className="flex items-center gap-1.5">
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: severityColor(sev) }} />
            <span className="mono text-xs font-bold" style={{ color: severityColor(sev) }}>{sevCounts[sev]}</span>
            <span className="text-xs capitalize" style={{ color: COLOR.text.muted }}>{sev}</span>
          </div>
        ))}
        <div className="flex-1" />
        <span className="text-xs" style={{ color: COLOR.text.muted }}>
          {findings.length} total{hiddenCount > 0 && ` · ${hiddenCount} locked`}
        </span>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 px-5 py-2 shrink-0" style={{ borderBottom: `1px solid ${COLOR.bg.border}` }}>
        {([
          { id: 'findings' as TabId,     label: `Findings (${findings.length})` },
          { id: 'intelligence' as TabId, label: 'Intelligence' },
          { id: 'graph' as TabId,        label: 'Attack Graph' },
        ]).map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className="px-4 py-1.5 rounded text-xs font-semibold transition-colors"
            style={{
              background: activeTab === id ? 'rgba(46,165,95,0.1)' : 'transparent',
              color: activeTab === id ? COLOR.accent : COLOR.text.muted,
              border: activeTab === id ? '1px solid rgba(46,165,95,0.25)' : '1px solid transparent',
              cursor: 'pointer',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto">

        {/* Findings */}
        {activeTab === 'findings' && (
          <>
            <table className="sx-table" style={{ tableLayout: 'fixed', width: '100%' }}>
              <colgroup>
                <col style={{ width: 88 }} /><col />
                <col style={{ width: 110 }} /><col style={{ width: 108 }} />
                <col style={{ width: 78 }} /><col style={{ width: 108 }} />
              </colgroup>
              <thead style={{ position: 'sticky', top: 0, background: COLOR.bg.base, zIndex: 10 }}>
                <tr><th>Severity</th><th>Title</th><th>OWASP</th><th>CVE</th><th>Validated</th><th>Tool</th></tr>
              </thead>
              <tbody>
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-16" style={{ color: COLOR.text.muted }}>
                      {isRunning ? 'Waiting for first finding…' : 'No findings recorded'}
                    </td>
                  </tr>
                )}
                {findings.map((f, i) => (
                  <FindingRow
                    key={i}
                    finding={f}
                    index={i}
                    gated={isFreeTier && i >= 5}
                    isNew={newFindingIds.has(i)}
                    isKev={Boolean(f.cve_id && kevCveIds.has(f.cve_id))}
                    onSelect={setSelected}
                  />
                ))}
              </tbody>
            </table>

            {isFreeTier && hiddenCount > 0 && (
              <div className="mx-4 my-4 flex items-center justify-between gap-4 px-5 py-4 rounded-xl" style={{ background: 'rgba(46,165,95,0.04)', border: '1px solid rgba(46,165,95,0.18)' }}>
                <div className="flex items-center gap-3">
                  <Lock size={15} style={{ color: COLOR.accent }} />
                  <div>
                    <p className="text-sm font-semibold" style={{ color: COLOR.text.primary }}>{hiddenCount} more findings locked</p>
                    <p className="text-xs" style={{ color: COLOR.text.muted }}>{scan.results?.upgrade_message}</p>
                  </div>
                </div>
                <button className="btn-primary text-sm shrink-0" style={{ padding: '7px 16px' }}>Upgrade to Pro</button>
              </div>
            )}
          </>
        )}

        {/* Intelligence */}
        {activeTab === 'intelligence' && (
          <div className="max-w-3xl mx-auto px-5 py-6 space-y-6">

            {/* Risk gauge */}
            <div className="card flex flex-col items-center py-8">
              <p className="text-xs font-semibold uppercase tracking-widest mb-5" style={{ color: COLOR.text.muted }}>Composite Risk Score</p>
              <RiskGauge score={riskScore} size={180} />
            </div>

            {/* Executive summary */}
            <div className="card" style={{ borderLeft: `3px solid ${COLOR.accent}` }}>
              <div className="flex items-center gap-2 mb-3">
                <Brain size={13} style={{ color: COLOR.slate['300'] }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>Executive Summary</span>
              </div>
              {report?.executive_summary
                ? <p className="text-sm leading-relaxed" style={{ color: COLOR.text.secondary }}>{report.executive_summary}</p>
                : <p className="text-xs italic" style={{ color: COLOR.text.muted }}>{isRunning ? 'Analysis appears after scan completes…' : 'No AI report available'}</p>
              }
            </div>

            {/* Attack chains */}
            {report?.attack_chains && report.attack_chains.length > 0 && (
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <Zap size={13} style={{ color: COLOR.warn }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>
                    Attack Chains ({report.attack_chains.length})
                  </span>
                </div>
                <div className="space-y-3">
                  {report.attack_chains.map((chain, i) => <AttackChainCard key={i} chain={chain} idx={i} />)}
                </div>
              </div>
            )}

            {/* OWASP coverage */}
            <div className="card">
              <div className="flex items-center gap-2 mb-5">
                <Shield size={13} style={{ color: COLOR.accent }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>OWASP Top 10 Coverage</span>
              </div>
              {report?.owasp_coverage
                ? <OWASPBars coverage={report.owasp_coverage} />
                : <div className="flex flex-col items-center py-8 gap-2" style={{ color: COLOR.text.muted }}><Shield size={22} /><p className="text-xs">Coverage map available after analysis</p></div>
              }
            </div>

            {/* KEV matches */}
            {scan.kev_matches && scan.kev_matches.length > 0 && (
              <div className="card" style={{ borderColor: `${COLOR.danger}35` }}>
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle size={13} style={{ color: COLOR.danger }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.danger }}>
                    Known Exploited CVEs ({scan.kev_matches.length})
                  </span>
                </div>
                <div className="space-y-2">
                  {scan.kev_matches.map(cve => (
                    <div key={cve} className="flex items-center gap-3 px-3 py-2 rounded" style={{ background: `${COLOR.danger}07`, border: `1px solid ${COLOR.danger}1f` }}>
                      <span style={{ color: COLOR.warn }}>⚡</span>
                      <span className="mono font-semibold text-sm" style={{ color: '#fca5a5' }}>{cve}</span>
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer" className="text-xs hover:underline ml-auto" style={{ color: COLOR.text.muted }}>NVD ↗</a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation priorities */}
            {report?.remediation_priorities && report.remediation_priorities.length > 0 && (
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <CheckCircle2 size={13} style={{ color: COLOR.success }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>Remediation Priorities</span>
                </div>
                {report.remediation_priorities.slice(0, 6).map((item, i) => {
                  const ec = item.effort === 'low' ? COLOR.success : item.effort === 'medium' ? COLOR.warn : COLOR.danger
                  return (
                    <div key={i} className="flex gap-3 py-3" style={{ borderBottom: `1px solid rgba(30,46,40,0.5)` }}>
                      <div className="flex items-center justify-center rounded mono text-xs font-bold shrink-0" style={{ width: 22, height: 22, background: 'rgba(46,165,95,0.08)', color: COLOR.accent, marginTop: 2 }}>
                        {item.priority}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold mb-0.5 truncate" style={{ color: COLOR.text.primary }}>{item.finding}</p>
                        <p className="text-xs leading-relaxed" style={{ color: COLOR.text.muted }}>{item.action}</p>
                      </div>
                      <span className="text-xs font-semibold shrink-0 mt-1" style={{ color: ec }}>{item.effort}</span>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Analyst notes */}
            {report?.analyst_notes && (
              <div className="card">
                <div className="flex items-center gap-2 mb-3">
                  <Brain size={12} style={{ color: COLOR.slate['300'] }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>Analyst Notes</span>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: COLOR.text.muted }}>{report.analyst_notes}</p>
                {report.model_used && <p className="text-xs mt-2 mono" style={{ color: COLOR.text.muted }}>Model: {report.model_used}</p>}
              </div>
            )}
          </div>
        )}

        {/* Graph */}
        {activeTab === 'graph' && (
          <div className="p-5">
            <ExecutionGraph
              graphData={scan?.execution_graph ?? null}
              liveNodes={liveNodes}
              liveEdges={liveEdges}
              isRunning={isRunning}
              onFindingClick={setSelected}
            />
          </div>
        )}
      </div>

      {/* Finding drawer */}
      {selected && (
        <FindingDrawer
          finding={selected}
          isKev={Boolean(selected.cve_id && kevCveIds.has(selected.cve_id))}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}
