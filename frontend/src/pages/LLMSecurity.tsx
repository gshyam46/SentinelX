import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Brain, AlertTriangle, CheckCircle2,
  XCircle, ChevronDown, ChevronUp, RefreshCw,
} from 'lucide-react'
import { api, type LLMSecurityReport, type LLMCheck } from '../lib/api'
import { COLOR } from '../lib/theme'

const RISK_LABEL: Record<string, string> = {
  low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical',
}

function riskLabel(score: number): { label: string; color: string } {
  if (score <= 2)  return { label: 'Low',      color: COLOR.success }
  if (score <= 5)  return { label: 'Medium',   color: COLOR.warn    }
  if (score <= 7)  return { label: 'High',     color: COLOR.severity.high }
  return               { label: 'Critical',  color: COLOR.danger  }
}

// ── Evidence accordion ────────────────────────────────────────────────────

function EvidenceList({ evidence }: { evidence: string[] }) {
  const [open, setOpen] = useState(false)
  if (evidence.length === 0) return null
  return (
    <div className="mt-3">
      <button
        className="flex items-center gap-1 text-xs"
        style={{ color: COLOR.slate['300'], background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
        {open ? 'Hide' : 'Show'} evidence ({evidence.length})
      </button>
      {open && (
        <ul className="mt-2 space-y-1">
          {evidence.map((e, i) => (
            <li key={i} className="text-xs mono px-2 py-1 rounded" style={{ background: COLOR.bg.surface, color: COLOR.text.secondary, border: `1px solid ${COLOR.bg.border}` }}>
              {e}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ── Check card ────────────────────────────────────────────────────────────

function CheckCard({ check }: { check: LLMCheck }) {
  const detected = check.detected
  return (
    <div
      className="card"
      style={{ borderLeft: `3px solid ${detected ? COLOR.danger : COLOR.success}` }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span
            className="mono text-xs px-2 py-0.5 rounded font-bold"
            style={{
              background: detected ? 'rgba(229,59,59,0.1)' : 'rgba(46,165,95,0.1)',
              color: detected ? COLOR.danger : COLOR.success,
              border: `1px solid ${detected ? 'rgba(229,59,59,0.25)' : 'rgba(46,165,95,0.25)'}`,
            }}
          >
            {check.check_id}
          </span>
          <span className="font-semibold text-sm" style={{ color: COLOR.text.primary }}>{check.title}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {detected
            ? <XCircle size={15} style={{ color: COLOR.danger }} />
            : <CheckCircle2 size={15} style={{ color: COLOR.success }} />
          }
          <span className="text-xs font-semibold" style={{ color: detected ? COLOR.danger : COLOR.success }}>
            {detected ? 'Detected' : 'Clear'}
          </span>
        </div>
      </div>

      {check.description && (
        <p className="text-xs mt-2 leading-relaxed" style={{ color: COLOR.text.muted }}>{check.description}</p>
      )}

      {/* Confidence bar */}
      <div className="mt-3">
        <div className="flex justify-between text-xs mb-1" style={{ color: COLOR.text.muted }}>
          <span>Confidence</span>
          <span className="mono">{Math.round(check.confidence * 100)}%</span>
        </div>
        <div className="progress-bar">
          <div className="progress-fill" style={{
            width: `${check.confidence * 100}%`,
            background: detected ? COLOR.danger : COLOR.success,
          }} />
        </div>
      </div>

      <EvidenceList evidence={check.evidence} />
    </div>
  )
}

// ── Attack chain strip ────────────────────────────────────────────────────

function ChainStrip({ chain, idx }: { chain: { name: string; steps: string[]; impact: string }; idx: number }) {
  const c = chain.impact === 'high' ? COLOR.danger : chain.impact === 'medium' ? COLOR.warn : COLOR.success
  return (
    <div className="rounded-lg p-3" style={{ border: `1px solid ${c}30`, background: `${c}07` }}>
      <div className="flex items-center gap-2 mb-2">
        <span className="mono text-xs font-bold" style={{ color: c }}>{idx + 1}</span>
        <span className="font-semibold text-sm" style={{ color: COLOR.text.primary }}>{chain.name}</span>
        <span className="ml-auto text-xs font-bold uppercase" style={{ color: c }}>{chain.impact}</span>
      </div>
      <div className="flex items-center flex-wrap gap-1">
        {chain.steps.map((step, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span style={{ color: COLOR.text.muted, fontSize: 10 }}>→</span>}
            <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: COLOR.bg.surface, color: COLOR.text.secondary }}>{step}</span>
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────

export default function LLMSecurity() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate   = useNavigate()

  const [report, setReport]   = useState<LLMSecurityReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState<string | null>(null)
  const [ran, setRan]         = useState(false)

  // Try to load existing report on mount
  useEffect(() => {
    if (!scanId) return
    ;(async () => {
      try {
        const r = await api.getLLMSecurityReport(scanId)
        setReport(r); setRan(true)
      } catch { /* no report yet */ }
    })()
  }, [scanId])

  async function runAudit() {
    if (!scanId) return
    setLoading(true); setError(null)
    try {
      const r = await api.getLLMSecurityReport(scanId)
      setReport(r); setRan(true)
    } catch {
      setError('LLM Security audit failed or is not available for this scan.')
    } finally {
      setLoading(false)
    }
  }

  const detected  = report ? report.checks.filter(c => c.detected).length : 0
  const risk      = report ? riskLabel(report.risk_score) : null

  return (
    <div style={{ minHeight: '100vh', background: COLOR.bg.base }}>

      {/* Top bar */}
      <div
        className="flex items-center gap-4 px-5 py-4 sticky top-0 z-20"
        style={{ borderBottom: `1px solid ${COLOR.bg.border}`, background: `${COLOR.bg.base}f0`, backdropFilter: 'blur(16px)' }}
      >
        <button
          className="flex items-center gap-1 text-xs"
          style={{ color: COLOR.text.muted, background: 'none', border: 'none', cursor: 'pointer' }}
          onClick={() => navigate(`/scans/${scanId}`)}
        >
          <ArrowLeft size={12} /> Back to Scan
        </button>

        <div style={{ width: 1, height: 18, background: COLOR.bg.border }} />

        <div className="flex items-center gap-2">
          <Brain size={14} style={{ color: COLOR.slate['300'] }} />
          <span className="font-semibold text-sm" style={{ color: COLOR.text.primary }}>LLM Security Audit</span>
          <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(74,109,130,0.1)', color: COLOR.slate['300'], border: `1px solid ${COLOR.slate['600']}` }}>
            OWASP LLM Top 10
          </span>
        </div>

        <div className="flex-1" />

        <button
          className="btn-primary"
          style={{ padding: '7px 16px', fontSize: 12 }}
          onClick={runAudit}
          disabled={loading}
        >
          {loading
            ? <><RefreshCw size={12} className="spin" /> Running 10 OWASP LLM checks…</>
            : ran ? 'Re-run Audit' : 'Run LLM Security Audit'
          }
        </button>
      </div>

      <div className="px-5 py-6" style={{ maxWidth: 1100 }}>

        {/* Not-run state */}
        {!ran && !loading && !error && (
          <div className="flex flex-col items-center justify-center py-20 gap-5">
            <div className="flex items-center justify-center rounded-2xl" style={{ width: 60, height: 60, background: 'rgba(74,109,130,0.1)', border: `1px solid ${COLOR.slate['600']}` }}>
              <Brain size={28} style={{ color: COLOR.slate['300'] }} />
            </div>
            <div className="text-center">
              <h2 className="font-bold text-lg mb-2" style={{ color: COLOR.text.primary }}>LLM Security Audit</h2>
              <p className="text-sm" style={{ color: COLOR.text.muted, maxWidth: 380 }}>
                Run all 10 OWASP LLM Top 10 checks against this scan's findings and AI model interactions.
              </p>
            </div>
            <button className="btn-primary" onClick={runAudit} disabled={loading}>
              <Brain size={14} /> Run LLM Security Audit
            </button>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 p-4 rounded-lg" style={{ background: 'rgba(229,59,59,0.07)', border: '1px solid rgba(229,59,59,0.2)', color: '#fca5a5' }}>
            <AlertTriangle size={14} />
            <span className="text-sm">{error}</span>
          </div>
        )}

        {report && (
          <>
            {/* Risk score header */}
            <div className="card flex items-center gap-8 mb-6">
              <div className="flex items-end gap-2">
                <span className="text-5xl font-bold mono" style={{ color: risk?.color }}>
                  {report.risk_score.toFixed(1)}
                </span>
                <span className="text-xl mb-1" style={{ color: COLOR.text.muted }}>/ 10</span>
              </div>
              <div>
                <div className="font-bold text-xl mb-1" style={{ color: risk?.color }}>
                  {risk?.label} Risk
                </div>
                <div className="text-sm" style={{ color: COLOR.text.muted }}>
                  {detected} of {report.checks.length} checks detected vulnerabilities
                </div>
              </div>
              <div className="flex-1" />
              <div className="flex flex-col items-end gap-1">
                <div className="flex items-center gap-2">
                  <XCircle size={13} style={{ color: COLOR.danger }} />
                  <span className="text-sm" style={{ color: COLOR.text.secondary }}>{detected} detected</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={13} style={{ color: COLOR.success }} />
                  <span className="text-sm" style={{ color: COLOR.text.secondary }}>{report.checks.length - detected} clear</span>
                </div>
              </div>
            </div>

            {/* Summary */}
            {report.summary && (
              <div className="card mb-6" style={{ borderLeft: `3px solid ${COLOR.slate['400']}` }}>
                <div className="flex items-center gap-2 mb-2">
                  <Brain size={12} style={{ color: COLOR.slate['300'] }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>Summary</span>
                </div>
                <p className="text-sm leading-relaxed" style={{ color: COLOR.text.secondary }}>{report.summary}</p>
              </div>
            )}

            {/* 10 checks in 2-col grid */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              {report.checks.map((check) => (
                <CheckCard key={check.check_id} check={check} />
              ))}
            </div>

            {/* Attack chains */}
            {report.attack_chains.length > 0 && (
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle size={13} style={{ color: COLOR.warn }} />
                  <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>
                    LLM Attack Chains ({report.attack_chains.length})
                  </span>
                </div>
                <div className="space-y-3">
                  {report.attack_chains.map((chain, i) => <ChainStrip key={i} chain={chain} idx={i} />)}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
