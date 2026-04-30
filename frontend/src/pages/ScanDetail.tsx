import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Globe, Clock, RefreshCw, Lock,
  AlertTriangle, Shield, Zap, Brain, TrendingUp,
  CheckCircle2, X, ChevronRight, Cpu, Activity,
  Wrench, BookOpen, ShieldAlert, Link2,
} from 'lucide-react'
import { api, useScanLive, type ScanResultResponse, type Finding, type AnalysisReport, type LiveEvent } from '../lib/api'
import { severityColor, riskColor, formatRelativeTime } from '../lib/utils'
import { ACCENT, SEVERITY_COLOR, BG, WARN, SUCCESS, DANGER } from '../lib/theme'
import RiskGauge from '../components/RiskGauge'
import FindingRow from '../components/FindingRow'
import ExecutionGraph from '../components/ExecutionGraph'

// ── OWASP ─────────────────────────────────────────────────────────────────────

const OWASP_CATS = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']
const OWASP_NAMES: Record<string, string> = {
  A01: 'Broken Access Control', A02: 'Cryptographic Failures', A03: 'Injection',
  A04: 'Insecure Design', A05: 'Security Misconfiguration', A06: 'Vulnerable Components',
  A07: 'Auth Failures', A08: 'Data Integrity Failures', A09: 'Logging Failures',
  A10: 'SSRF',
}

// ── Finding Drawer ────────────────────────────────────────────────────────────

const EXPLOITABILITY: Record<string, { label: string; score: number }> = {
  critical: { label: 'Trivial',    score: 9 },
  high:     { label: 'Easy',       score: 7 },
  medium:   { label: 'Moderate',   score: 5 },
  low:      { label: 'Difficult',  score: 3 },
  info:     { label: 'N/A',        score: 1 },
}

function FindingDrawer({ finding, isKev, onClose }: { finding: Finding; isKev: boolean; onClose: () => void }) {
  const sev = finding.severity
  const color = severityColor(sev)
  const exploit = EXPLOITABILITY[sev] ?? EXPLOITABILITY.info

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: 'rgba(0,0,0,0.5)' }}
        onClick={onClose}
      />
      {/* Drawer */}
      <div
        className="drawer-slide fixed right-0 top-0 bottom-0 z-50 overflow-y-auto"
        style={{ width: 480, background: BG.surface, borderLeft: `1px solid ${BG.border}` }}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between px-6 py-5 sticky top-0"
          style={{ background: BG.surface, borderBottom: `1px solid ${BG.border}` }}
        >
          <div className="flex-1 min-w-0 pr-4">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`badge badge-${sev}`}>{sev.toUpperCase()}</span>
              {isKev && (
                <span
                  className="text-xs px-1.5 py-0.5 rounded font-bold"
                  style={{ background: 'rgba(245,158,11,0.15)', color: WARN, border: '1px solid rgba(245,158,11,0.3)' }}
                >
                  ⚡ KEV
                </span>
              )}
            </div>
            <h3 className="font-semibold text-sm leading-snug" style={{ color: '#f9fafb' }}>
              {finding.title}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-white/5 shrink-0"
            style={{ color: '#6b7280' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-6">
          {/* KEV banner */}
          {isKev && (
            <div className="rounded-lg px-4 py-3" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)' }}>
              <div className="flex items-center gap-2 mb-1">
                <Zap size={13} style={{ color: WARN }} />
                <span className="text-xs font-bold" style={{ color: WARN }}>KNOWN EXPLOITED VULNERABILITY</span>
              </div>
              <p className="text-xs leading-relaxed" style={{ color: '#fde68a' }}>
                This CVE appears in CISA's Known Exploited Vulnerabilities catalog. Active exploitation in the wild has been confirmed.
              </p>
            </div>
          )}

          {/* Description */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert size={13} style={{ color: '#9ca3af' }} />
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>Description</span>
            </div>
            <p className="text-sm leading-relaxed" style={{ color: '#d1d5db' }}>
              {finding.description}
            </p>
          </div>

          {/* Exploitability */}
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider block mb-2" style={{ color: '#6b7280' }}>
              Exploitability
            </span>
            <div className="flex items-center gap-3 mb-2">
              <span className="font-semibold text-sm" style={{ color }}>{exploit.label}</span>
              <span className="text-xs font-mono" style={{ color: '#4b5563' }}>{exploit.score}/10</span>
            </div>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${exploit.score * 10}%`, background: color }} />
            </div>
          </div>

          {/* OWASP categories */}
          {finding.owasp_categories.length > 0 && (
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider block mb-2" style={{ color: '#6b7280' }}>
                OWASP Categories
              </span>
              <div className="flex flex-wrap gap-2">
                {finding.owasp_categories.map(cat => (
                  <div key={cat} className="flex items-center gap-1.5">
                    <span
                      className="font-mono text-xs px-2 py-0.5 rounded"
                      style={{ background: 'rgba(0,212,255,0.06)', color: '#67e8f9', border: '1px solid rgba(0,212,255,0.15)' }}
                    >
                      {cat}
                    </span>
                    <span className="text-xs" style={{ color: '#6b7280' }}>{OWASP_NAMES[cat] ?? cat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Business impact */}
          <div className="rounded-lg p-4" style={{ background: `${color}08`, border: `1px solid ${color}20` }}>
            <div className="flex items-center gap-2 mb-2">
              <Link2 size={12} style={{ color }} />
              <span className="text-xs font-semibold" style={{ color }}>Business Impact</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: '#d1d5db' }}>
              {sev === 'critical'
                ? 'Immediate threat to system integrity. Exploitation could lead to full compromise, data exfiltration, or service disruption.'
                : sev === 'high'
                ? 'Significant risk to confidentiality or availability. Exploitation may grant unauthorized access or cause data exposure.'
                : sev === 'medium'
                ? 'Moderate risk that may be chained with other vulnerabilities for greater impact.'
                : 'Limited direct impact; should be addressed to maintain security posture.'}
            </p>
          </div>

          {/* Remediation */}
          {finding.remediation && (
            <div className="rounded-lg p-4" style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)' }}>
              <div className="flex items-center gap-2 mb-2">
                <Wrench size={12} style={{ color: SUCCESS }} />
                <span className="text-xs font-semibold" style={{ color: SUCCESS }}>Remediation Steps</span>
              </div>
              <p className="text-xs leading-relaxed font-mono" style={{ color: '#d1d5db' }}>
                {finding.remediation}
              </p>
            </div>
          )}

          {/* CVE reference */}
          {finding.cve_id && (
            <div className="flex items-center gap-3">
              <BookOpen size={12} style={{ color: '#6b7280' }} />
              <span className="text-xs" style={{ color: '#6b7280' }}>Reference:</span>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs font-mono hover:underline"
                style={{ color: '#67e8f9' }}
              >
                {finding.cve_id} ↗
              </a>
            </div>
          )}

          {/* Metadata */}
          <div className="pt-2" style={{ borderTop: `1px solid ${BG.border}` }}>
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: '#4b5563' }}>Target:</span>
                <span className="text-xs font-mono" style={{ color: '#9ca3af' }}>{finding.target}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: '#4b5563' }}>Tool:</span>
                <span className="text-xs font-mono" style={{ color: '#9ca3af' }}>{finding.source_tool}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs" style={{ color: '#4b5563' }}>Discovered:</span>
                <span className="text-xs" style={{ color: '#9ca3af' }}>
                  {new Date(finding.discovered_at).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

// ── OWASP Coverage Bars ───────────────────────────────────────────────────────

function OWASPCoverageBars({ coverage }: { coverage: Record<string, string> }) {
  return (
    <div className="space-y-3">
      {OWASP_CATS.map(cat => {
        const val = coverage[cat] ?? 'missing'
        const pct = val === 'covered' ? 100 : val === 'partial' ? 50 : 0
        const color = val === 'covered' ? SUCCESS : val === 'partial' ? WARN : BG.border
        return (
          <div key={cat}>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold" style={{ color: '#9ca3af', minWidth: 28 }}>{cat}</span>
                <span className="text-xs" style={{ color: '#4b5563' }}>{OWASP_NAMES[cat]}</span>
              </div>
              <span
                className="text-xs font-semibold capitalize"
                style={{ color: val === 'covered' ? SUCCESS : val === 'partial' ? WARN : '#374151' }}
              >
                {val}
              </span>
            </div>
            <div className="progress-bar">
              <div style={{ height: '100%', borderRadius: 99, width: `${pct}%`, background: color, transition: 'width 0.6s ease' }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Attack Chain ──────────────────────────────────────────────────────────────

function AttackChain({ chain, idx }: { chain: { name: string; steps: string[]; impact: string }; idx: number }) {
  const impactColor = chain.impact === 'high' ? DANGER : chain.impact === 'medium' ? WARN : SUCCESS
  return (
    <div className="rounded-lg p-4" style={{ border: `1px solid ${BG.border}`, background: 'rgba(0,0,0,0.2)' }}>
      <div className="flex items-center gap-3 mb-3">
        <div
          className="flex items-center justify-center rounded font-mono text-xs font-bold"
          style={{ width: 22, height: 22, background: `${DANGER}15`, color: DANGER }}
        >
          {idx + 1}
        </div>
        <span className="font-semibold text-sm flex-1" style={{ color: '#e5e7eb' }}>{chain.name}</span>
        <span className="text-xs font-bold" style={{ color: impactColor }}>{chain.impact.toUpperCase()}</span>
      </div>
      <div className="flex items-center flex-wrap gap-1.5">
        {chain.steps.map((step, i) => (
          <React.Fragment key={i}>
            {i > 0 && (
              <ChevronRight size={12} style={{ color: ACCENT, flexShrink: 0 }} />
            )}
            <span
              className="text-xs px-2 py-1 rounded"
              style={{ background: BG.surface, color: '#9ca3af', border: `1px solid ${BG.border}` }}
            >
              {step}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

// ── Main ScanDetail ───────────────────────────────────────────────────────────

type TabId = 'findings' | 'intelligence' | 'graph'

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()

  const [scan, setScan] = useState<ScanResultResponse | null>(null)
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [liveFindings, setLiveFindings] = useState<Finding[]>([])
  const [newFindingIds, setNewFindingIds] = useState<Set<number>>(new Set())
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<TabId>('findings')
  const [pdfDownloading, setPdfDownloading] = useState(false)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const newFindingTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Live graph state
  const [liveGraphNodes, setLiveGraphNodes] = useState<Array<{ id: string; type: string; data: Record<string, unknown> }>>([])
  const [liveGraphEdges, setLiveGraphEdges] = useState<Array<{ id: string; source: string; target: string; relationship?: string }>>([])

  // Tool elapsed time tracking
  const toolStartTimes = useRef<Map<string, number>>(new Map())
  const [tickCount, setTickCount] = useState(0)

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
        try {
          const rep = await api.getScanReport(scanId)
          if (alive) setReport(rep)
        } catch { /* not ready */ }
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
        if (serverFindings.length > liveFindings.length) setLiveFindings(serverFindings)
      } catch { /* ignore */ }
    }, 5000)
    return () => clearInterval(id)
  }, [scanId, scan?.status, liveFindings.length])

  const handleNewFinding = useCallback((f: Finding) => {
    setLiveFindings(prev => {
      const idx = prev.length
      setNewFindingIds(s => new Set(s).add(idx))
      if (newFindingTimer.current) clearTimeout(newFindingTimer.current)
      newFindingTimer.current = setTimeout(() => setNewFindingIds(new Set()), 2000)
      return [...prev, f]
    })
  }, [])

  const handleScanComplete = useCallback(async () => {
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
  }, [scanId])

  // ── WS live event handler ──────────────────────────────────────────
  const handleLiveEvent = useCallback((event: LiveEvent) => {
    if (event.type === 'tool_started' && event.tool) {
      toolStartTimes.current.set(event.tool, Date.now())
      setLiveGraphNodes(prev => {
        if (prev.find(n => n.id === `live_tool_${event.tool}`)) return prev
        return [...prev, { id: `live_tool_${event.tool}`, type: 'tool_execution', data: { tool_name: event.tool, status: 'running' } }]
      })
    }
    if (event.type === 'tool_complete' && event.tool) {
      setLiveGraphNodes(prev => prev.map(n =>
        n.id === `live_tool_${event.tool}` ? { ...n, data: { ...n.data, status: 'complete' } } : n
      ))
    }
    if (event.type === 'finding' && event.finding) {
      handleNewFinding(event.finding)
      const f = event.finding
      const nodeId = `live_finding_${Date.now()}`
      setLiveGraphNodes(prev => [...prev, {
        id: nodeId, type: 'finding',
        data: { title: f.title, severity: f.severity, known_exploited: f.known_exploited ?? false },
      }])
      if (event.tool) {
        setLiveGraphEdges(prev => [...prev, {
          id: `live_edge_${nodeId}`,
          source: `live_tool_${event.tool}`,
          target: nodeId,
          relationship: 'triggered',
        }])
      }
    }
    if (event.type === 'report_ready' || event.type === 'stream_end') {
      handleScanComplete()
    }
  }, [handleNewFinding, handleScanComplete])

  const isRunning = scan?.status === 'running' || scan?.status === 'pending'

  const { toolsInProgress } = useScanLive(
    isRunning ? (scanId ?? null) : null,
    handleLiveEvent
  )

  // Tick for elapsed time
  useEffect(() => {
    if (!isRunning || toolsInProgress.size === 0) return
    const id = setInterval(() => setTickCount(n => n + 1), 1000)
    return () => clearInterval(id)
  }, [isRunning, toolsInProgress.size])
  void tickCount // used to trigger re-render

  async function handlePdfDownload() {
    if (!scanId || pdfDownloading) return
    setPdfDownloading(true)
    try {
      const blob = await api.downloadScanPdf(scanId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sentinelx-report-${scanId}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* fail silently */ }
    finally { setPdfDownloading(false) }
  }

  const findings = liveFindings
  const isFreeTier = !!(scan?.results?.gated)
  const hiddenCount = scan?.results?.hidden_findings_count ?? 0
  const riskScore = report?.risk_score ?? scan?.risk_score ?? 0
  const kevCveIds = new Set(scan?.kev_matches ?? [])

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++ })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ color: '#4b5563' }}>
        <RefreshCw size={22} className="spin" />
        <span className="ml-3 text-sm">Loading scan…</span>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-4" style={{ color: '#4b5563' }}>
        <AlertTriangle size={32} />
        <p className="text-sm">Scan not found</p>
        <button className="sx-btn sx-btn-ghost text-sm" onClick={() => navigate('/')}>
          <ArrowLeft size={13} /> Go back
        </button>
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-screen" style={{ background: BG.base }}>

      {/* ── Sticky top bar ── */}
      <div
        className="flex items-center gap-4 px-6 py-3 shrink-0 sticky top-0 z-30"
        style={{ borderBottom: `1px solid ${BG.border}`, background: 'rgba(10,14,26,0.95)', backdropFilter: 'blur(16px)' }}
      >
        <button
          className="flex items-center gap-1.5 text-xs hover:text-white transition-colors"
          style={{ color: '#6b7280' }}
          onClick={() => navigate('/')}
        >
          <ArrowLeft size={13} /> Back
        </button>

        <div style={{ width: 1, height: 20, background: BG.border }} />

        <div className="flex items-center gap-2">
          <Globe size={14} style={{ color: ACCENT }} />
          <span className="font-mono font-semibold text-sm" style={{ color: '#f9fafb' }}>{scan.domain}</span>
        </div>

        <span
          className="text-xs px-2 py-0.5 rounded font-semibold uppercase tracking-wider"
          style={{ background: 'rgba(0,212,255,0.08)', color: ACCENT, border: '1px solid rgba(0,212,255,0.2)' }}
        >
          {scan.scan_type}
        </span>

        {isRunning && (
          <div className="flex items-center gap-1.5">
            <div className="pulse-dot" style={{ width: 7, height: 7, borderRadius: '50%', background: ACCENT }} />
            <span className="text-xs font-semibold" style={{ color: ACCENT }}>LIVE</span>
          </div>
        )}

        <div className="flex-1" />

        {scan.status === 'complete' && (
          <button
            onClick={handlePdfDownload}
            disabled={pdfDownloading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
            style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', color: SUCCESS, cursor: pdfDownloading ? 'not-allowed' : 'pointer' }}
          >
            {pdfDownloading ? <RefreshCw size={11} className="spin" /> : <TrendingUp size={11} />}
            {pdfDownloading ? 'Generating…' : 'PDF Report'}
          </button>
        )}

        <span className={`badge badge-${scan.status}`}>{scan.status.toUpperCase()}</span>

        <div className="flex items-center gap-1.5">
          <Clock size={12} style={{ color: '#4b5563' }} />
          <span className="text-xs" style={{ color: '#6b7280' }}>{formatRelativeTime(scan.created_at)}</span>
        </div>
      </div>

      {/* ── Live tool status strip ── */}
      {isRunning && (
        <div
          className="flex items-center gap-4 px-6 py-2.5 shrink-0"
          style={{ borderBottom: `1px solid ${BG.border}`, background: 'rgba(0,212,255,0.03)' }}
        >
          <div className="flex items-center gap-1.5">
            <Cpu size={12} style={{ color: ACCENT }} />
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: ACCENT }}>Scanning</span>
          </div>
          <div className="flex items-center gap-4 flex-1 overflow-x-auto">
            {Array.from(toolsInProgress).map(tool => {
              const elapsed = toolStartTimes.current.has(tool)
                ? Math.floor((Date.now() - toolStartTimes.current.get(tool)!) / 1000)
                : 0
              return (
                <div key={tool} className="flex items-center gap-1.5 shrink-0">
                  <div className="pulse-dot" style={{ width: 5, height: 5, borderRadius: '50%', background: ACCENT }} />
                  <span className="font-mono text-xs font-semibold" style={{ color: '#67e8f9' }}>{tool}</span>
                  <span className="text-xs" style={{ color: '#4b5563' }}>{elapsed}s</span>
                </div>
              )
            })}
            {toolsInProgress.size === 0 && (
              <span className="text-xs" style={{ color: '#4b5563' }}>
                {scan.current_step ?? 'Initializing…'}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
              <span key={sev} className="font-mono text-xs">
                <span style={{ color: SEVERITY_COLOR[sev], fontWeight: 700 }}>{sevCounts[sev]}</span>
                <span style={{ color: '#374151' }}>{sev[0].toUpperCase()}</span>
              </span>
            ))}
            <span className="text-xs font-mono" style={{ color: '#6b7280' }}>{findings.length} findings</span>
          </div>
        </div>
      )}

      {/* ── Severity summary ── */}
      <div
        className="flex items-center gap-6 px-6 py-2.5 shrink-0"
        style={{ borderBottom: `1px solid ${BG.border}`, background: 'rgba(0,0,0,0.15)' }}
      >
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
          <div key={sev} className="flex items-center gap-1.5">
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: SEVERITY_COLOR[sev] }} />
            <span className="font-mono text-xs font-bold" style={{ color: SEVERITY_COLOR[sev] }}>{sevCounts[sev]}</span>
            <span className="text-xs capitalize" style={{ color: '#6b7280' }}>{sev}</span>
          </div>
        ))}
        <div className="flex-1" />
        <span className="text-xs" style={{ color: '#6b7280' }}>
          {findings.length} total{hiddenCount > 0 && ` · ${hiddenCount} locked`}
        </span>
      </div>

      {/* ── Tabs ── */}
      <div
        className="flex items-center gap-1 px-6 py-2 shrink-0"
        style={{ borderBottom: `1px solid ${BG.border}` }}
      >
        {([
          { id: 'findings' as TabId, label: `Findings (${findings.length})` },
          { id: 'intelligence' as TabId, label: 'Intelligence' },
          { id: 'graph' as TabId, label: 'Attack Graph' },
        ]).map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className="px-4 py-1.5 rounded text-xs font-semibold transition-colors"
            style={{
              background: activeTab === id ? 'rgba(0,212,255,0.1)' : 'transparent',
              color: activeTab === id ? ACCENT : '#6b7280',
              border: activeTab === id ? '1px solid rgba(0,212,255,0.25)' : '1px solid transparent',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Tab Content ── */}
      <div className="flex-1 overflow-y-auto">

        {/* ── Findings tab ── */}
        {activeTab === 'findings' && (
          <>
            <table className="sx-table" style={{ tableLayout: 'fixed', width: '100%' }}>
              <colgroup>
                <col style={{ width: 90 }} />
                <col />
                <col style={{ width: 110 }} />
                <col style={{ width: 110 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 110 }} />
              </colgroup>
              <thead style={{ position: 'sticky', top: 0, background: BG.base, zIndex: 10 }}>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>OWASP</th>
                  <th>CVE</th>
                  <th>Validated</th>
                  <th>Tool</th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-16" style={{ color: '#4b5563' }}>
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
                    onSelect={setSelectedFinding}
                  />
                ))}
              </tbody>
            </table>

            {isFreeTier && hiddenCount > 0 && (
              <div
                className="mx-4 my-4 flex items-center justify-between gap-4 px-5 py-4 rounded-xl"
                style={{ background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.2)' }}
              >
                <div className="flex items-center gap-3">
                  <Lock size={16} style={{ color: ACCENT }} />
                  <div>
                    <p className="text-sm font-semibold" style={{ color: '#e5e7eb' }}>{hiddenCount} more findings locked</p>
                    <p className="text-xs" style={{ color: '#6b7280' }}>{scan.results?.upgrade_message}</p>
                  </div>
                </div>
                <button className="sx-btn text-sm shrink-0" style={{ padding: '8px 18px' }}>Upgrade to Pro</button>
              </div>
            )}
          </>
        )}

        {/* ── Intelligence tab ── */}
        {activeTab === 'intelligence' && (
          <div className="max-w-4xl mx-auto px-6 py-6 space-y-8">
            {/* Risk gauge */}
            <div className="glass px-8 py-6 flex flex-col items-center">
              <p className="text-xs font-semibold uppercase tracking-widest mb-5" style={{ color: '#4b5563' }}>
                Composite Risk Score
              </p>
              <RiskGauge score={riskScore} size={180} />
            </div>

            {/* Executive summary */}
            <div className="glass px-6 py-5">
              <div className="flex items-center gap-2 mb-4">
                <Brain size={14} style={{ color: '#8b5cf6' }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>
                  Executive Summary
                </span>
              </div>
              {report?.executive_summary ? (
                <p className="text-sm leading-relaxed" style={{ color: '#d1d5db' }}>{report.executive_summary}</p>
              ) : (
                <p className="text-xs italic" style={{ color: '#4b5563' }}>
                  {isRunning ? 'Analysis will appear after scan completes…' : 'No AI report available'}
                </p>
              )}
            </div>

            {/* Attack chains */}
            {report?.attack_chains && report.attack_chains.length > 0 && (
              <div className="glass px-6 py-5">
                <div className="flex items-center gap-2 mb-4">
                  <Zap size={14} style={{ color: WARN }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>
                    Attack Chains ({report.attack_chains.length})
                  </span>
                </div>
                <div className="space-y-3">
                  {report.attack_chains.map((chain, i) => (
                    <AttackChain key={i} chain={chain} idx={i} />
                  ))}
                </div>
              </div>
            )}

            {/* OWASP coverage */}
            <div className="glass px-6 py-5">
              <div className="flex items-center gap-2 mb-5">
                <Shield size={14} style={{ color: ACCENT }} />
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>
                  OWASP Top 10 Coverage
                </span>
              </div>
              {report?.owasp_coverage ? (
                <OWASPCoverageBars coverage={report.owasp_coverage} />
              ) : (
                <div className="flex flex-col items-center py-8 gap-2" style={{ color: '#374151' }}>
                  <Shield size={24} />
                  <p className="text-xs">Coverage map available after analysis</p>
                </div>
              )}
            </div>

            {/* Known exploited CVEs */}
            {scan.kev_matches && scan.kev_matches.length > 0 && (
              <div
                className="glass px-6 py-5"
                style={{ borderColor: `${DANGER}40` }}
              >
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle size={14} style={{ color: DANGER }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: DANGER }}>
                    Known Exploited CVEs ({scan.kev_matches.length})
                  </span>
                </div>
                <div className="space-y-2">
                  {scan.kev_matches.map(cve => (
                    <div
                      key={cve}
                      className="flex items-center gap-3 px-3 py-2 rounded-lg"
                      style={{ background: `${DANGER}08`, border: `1px solid ${DANGER}20` }}
                    >
                      <span style={{ color: WARN, fontSize: 13 }}>⚡</span>
                      <span className="font-mono text-sm font-semibold" style={{ color: '#fca5a5' }}>{cve}</span>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs hover:underline ml-auto"
                        style={{ color: '#6b7280' }}
                        onClick={e => e.stopPropagation()}
                      >
                        NVD ↗
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation priorities */}
            {report?.remediation_priorities && report.remediation_priorities.length > 0 && (
              <div className="glass px-6 py-5">
                <div className="flex items-center gap-2 mb-4">
                  <CheckCircle2 size={14} style={{ color: SUCCESS }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>
                    Remediation Priorities
                  </span>
                </div>
                <div>
                  {report.remediation_priorities.slice(0, 6).map((item, i) => {
                    const effortColor = item.effort === 'low' ? SUCCESS : item.effort === 'medium' ? WARN : DANGER
                    return (
                      <div key={i} className="flex gap-3 py-3" style={{ borderBottom: `1px solid rgba(31,41,55,0.5)` }}>
                        <div
                          className="flex items-center justify-center rounded font-mono text-xs font-bold shrink-0"
                          style={{ width: 22, height: 22, background: 'rgba(0,212,255,0.08)', color: ACCENT, marginTop: 2 }}
                        >
                          {item.priority}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-semibold mb-0.5 truncate" style={{ color: '#e5e7eb' }}>{item.finding}</p>
                          <p className="text-xs leading-relaxed" style={{ color: '#9ca3af' }}>{item.action}</p>
                        </div>
                        <span className="text-xs font-semibold shrink-0 mt-1" style={{ color: effortColor }}>{item.effort}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Analyst notes */}
            {report?.analyst_notes && (
              <div className="glass px-6 py-5">
                <div className="flex items-center gap-2 mb-3">
                  <Brain size={13} style={{ color: '#8b5cf6' }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6b7280' }}>Analyst Notes</span>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: '#9ca3af' }}>{report.analyst_notes}</p>
                {report.model_used && (
                  <p className="text-xs mt-2 font-mono" style={{ color: '#374151' }}>Model: {report.model_used}</p>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Attack Graph tab ── */}
        {activeTab === 'graph' && (
          <div className="p-6">
            <ExecutionGraph
              graphData={scan?.execution_graph ?? null}
              liveNodes={liveGraphNodes}
              liveEdges={liveGraphEdges}
              isRunning={isRunning}
            />
          </div>
        )}
      </div>

      {/* ── Finding detail drawer ── */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          isKev={Boolean(selectedFinding.cve_id && kevCveIds.has(selectedFinding.cve_id))}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  )
}
