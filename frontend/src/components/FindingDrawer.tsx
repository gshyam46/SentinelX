import React, { useEffect } from 'react'
import {
  X, Zap, Wrench, BookOpen, ShieldAlert, Link2,
  CheckCircle2, XCircle, Clock, ExternalLink,
} from 'lucide-react'
import type { Finding } from '../lib/api'
import { severityColor, COLOR } from '../lib/theme'

interface Props {
  finding: Finding
  isKev?: boolean
  onClose: () => void
  onVerify?: (f: Finding) => void
}

const OWASP_NAMES: Record<string, string> = {
  A01: 'Broken Access Control',   A02: 'Cryptographic Failures',
  A03: 'Injection',               A04: 'Insecure Design',
  A05: 'Security Misconfiguration', A06: 'Vulnerable Components',
  A07: 'Auth Failures',           A08: 'Data Integrity Failures',
  A09: 'Logging Failures',        A10: 'SSRF',
}

const EXPLOITABILITY: Record<string, { label: string; score: number }> = {
  critical: { label: 'Trivial',   score: 9 },
  high:     { label: 'Easy',      score: 7 },
  medium:   { label: 'Moderate',  score: 5 },
  low:      { label: 'Difficult', score: 3 },
  info:     { label: 'N/A',       score: 1 },
}

function ValidatedBadge({ v }: { v: Finding['validated'] }) {
  if (v === 'confirmed')
    return <span style={{ color: COLOR.success, display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}><CheckCircle2 size={13} /> Confirmed</span>
  if (v === 'false_positive')
    return <span style={{ color: COLOR.danger, display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}><XCircle size={13} /> False positive</span>
  return <span style={{ color: COLOR.slate['300'], display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}><Clock size={13} /> Pending</span>
}

export default function FindingDrawer({ finding, isKev = false, onClose, onVerify }: Props) {
  const sev   = finding.severity
  const color = severityColor(sev)
  const expl  = EXPLOITABILITY[sev] ?? EXPLOITABILITY.info

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [onClose])

  return (
    <>
      <div
        className="fixed inset-0 z-40"
        style={{ background: 'rgba(0,0,0,0.55)' }}
        onClick={onClose}
      />

      <div
        className="drawer-slide fixed right-0 top-0 bottom-0 z-50 overflow-y-auto"
        style={{ width: 420, background: COLOR.bg.raised, borderLeft: `1px solid ${COLOR.bg.border}` }}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between px-5 py-4 sticky top-0"
          style={{ background: COLOR.bg.raised, borderBottom: `1px solid ${COLOR.bg.border}` }}
        >
          <div className="flex-1 min-w-0 pr-3">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className={`badge badge-${sev}`}>{sev.toUpperCase()}</span>
              {isKev && (
                <span className="badge" style={{ background: 'rgba(196,150,42,0.15)', color: COLOR.warn, border: '1px solid rgba(196,150,42,0.3)' }}>
                  ⚡ KEV
                </span>
              )}
            </div>
            <h3 className="font-semibold text-sm leading-snug" style={{ color: COLOR.text.primary }}>
              {finding.title}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg flex-shrink-0"
            style={{ color: COLOR.text.muted, background: 'transparent', border: 'none', cursor: 'pointer' }}
          >
            <X size={17} />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-5">

          {/* KEV banner */}
          {isKev && (
            <div className="rounded-lg px-4 py-3" style={{ background: 'rgba(196,150,42,0.07)', border: '1px solid rgba(196,150,42,0.22)' }}>
              <div className="flex items-center gap-2 mb-1">
                <Zap size={12} style={{ color: COLOR.warn }} />
                <span className="text-xs font-bold" style={{ color: COLOR.warn }}>KNOWN EXPLOITED VULNERABILITY</span>
              </div>
              <p className="text-xs leading-relaxed" style={{ color: '#e8d07a' }}>
                Listed in CISA's Known Exploited Vulnerabilities catalog. Active exploitation confirmed in the wild.
              </p>
            </div>
          )}

          {/* Description */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert size={12} style={{ color: COLOR.slate['300'] }} />
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: COLOR.text.muted }}>Description</span>
            </div>
            <p className="text-sm leading-relaxed" style={{ color: COLOR.text.secondary }}>
              {finding.description}
            </p>
          </div>

          {/* Exploitability */}
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider block mb-2" style={{ color: COLOR.text.muted }}>
              Exploitability
            </span>
            <div className="flex items-center gap-3 mb-2">
              <span className="font-semibold text-sm" style={{ color }}>{expl.label}</span>
              <span className="text-xs mono" style={{ color: COLOR.text.muted }}>{expl.score}/10</span>
            </div>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${expl.score * 10}%`, background: color }} />
            </div>
          </div>

          {/* Validated status */}
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider block mb-2" style={{ color: COLOR.text.muted }}>
              Validation Status
            </span>
            <ValidatedBadge v={finding.validated} />
            {finding.confidence !== undefined && (
              <div className="mt-2">
                <div className="flex justify-between text-xs mb-1" style={{ color: COLOR.text.muted }}>
                  <span>Confidence</span>
                  <span className="mono">{Math.round(finding.confidence * 100)}%</span>
                </div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${finding.confidence * 100}%` }} />
                </div>
              </div>
            )}
          </div>

          {/* Fix status */}
          {finding.fix_status && (
            <div className="rounded-lg px-4 py-3" style={{
              background: finding.fix_status === 'fixed'
                ? 'rgba(46,165,95,0.07)' : 'rgba(229,59,59,0.07)',
              border: `1px solid ${finding.fix_status === 'fixed'
                ? 'rgba(46,165,95,0.22)' : 'rgba(229,59,59,0.22)'}`,
            }}>
              <div className="flex items-center gap-2">
                {finding.fix_status === 'fixed'
                  ? <CheckCircle2 size={13} style={{ color: COLOR.success }} />
                  : <XCircle size={13} style={{ color: COLOR.danger }} />
                }
                <span className="text-xs font-semibold" style={{
                  color: finding.fix_status === 'fixed' ? COLOR.success : COLOR.danger,
                }}>
                  {finding.fix_status === 'fixed' ? 'Fixed ✓' : 'Still Present ✗'}
                </span>
              </div>
            </div>
          )}

          {/* OWASP */}
          {finding.owasp_categories.length > 0 && (
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider block mb-2" style={{ color: COLOR.text.muted }}>
                OWASP Categories
              </span>
              <div className="flex flex-wrap gap-2">
                {finding.owasp_categories.map(cat => (
                  <div key={cat} className="flex items-center gap-1.5">
                    <span className="mono text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(74,109,130,0.1)', color: COLOR.slate['300'], border: `1px solid ${COLOR.slate['600']}` }}>
                      {cat}
                    </span>
                    <span className="text-xs" style={{ color: COLOR.text.muted }}>{OWASP_NAMES[cat] ?? cat}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Business impact */}
          <div className="rounded-lg p-4" style={{ background: `${color}08`, border: `1px solid ${color}22` }}>
            <div className="flex items-center gap-2 mb-2">
              <Link2 size={11} style={{ color }} />
              <span className="text-xs font-semibold" style={{ color }}>Business Impact</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: COLOR.text.secondary }}>
              {sev === 'critical'
                ? 'Immediate threat. Exploitation could lead to full compromise, data exfiltration, or service disruption.'
                : sev === 'high'
                ? 'Significant risk. May grant unauthorized access or cause data exposure.'
                : sev === 'medium'
                ? 'Moderate risk. May be chained with other vulnerabilities for greater impact.'
                : 'Limited direct impact; address to maintain security posture.'}
            </p>
          </div>

          {/* Remediation */}
          {finding.remediation && (
            <div className="rounded-lg p-4" style={{ background: 'rgba(46,165,95,0.06)', border: '1px solid rgba(46,165,95,0.18)' }}>
              <div className="flex items-center gap-2 mb-2">
                <Wrench size={11} style={{ color: COLOR.success }} />
                <span className="text-xs font-semibold" style={{ color: COLOR.success }}>Remediation</span>
              </div>
              <p className="text-xs leading-relaxed mono" style={{ color: COLOR.text.secondary }}>
                {finding.remediation}
              </p>
            </div>
          )}

          {/* CVE */}
          {finding.cve_id && (
            <div className="flex items-center gap-3">
              <BookOpen size={11} style={{ color: COLOR.text.muted }} />
              <span className="text-xs" style={{ color: COLOR.text.muted }}>CVE Reference:</span>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs mono flex items-center gap-1 hover:underline"
                style={{ color: COLOR.slate['300'] }}
              >
                {finding.cve_id} <ExternalLink size={10} />
              </a>
            </div>
          )}

          {/* Metadata */}
          <div className="pt-3" style={{ borderTop: `1px solid ${COLOR.bg.border}` }}>
            {[
              ['Target', finding.target],
              ['Tool', finding.source_tool],
              ['Discovered', new Date(finding.discovered_at).toLocaleString()],
            ].map(([label, val]) => (
              <div key={label} className="flex items-center gap-2 mb-1.5">
                <span className="text-xs" style={{ color: COLOR.text.muted, minWidth: 70 }}>{label}:</span>
                <span className="text-xs mono" style={{ color: COLOR.text.secondary }}>{val}</span>
              </div>
            ))}
          </div>

          {/* Verify button */}
          {onVerify && (
            <button
              className="btn-primary w-full justify-center"
              onClick={() => onVerify(finding)}
            >
              Verify Fix
            </button>
          )}
        </div>
      </div>
    </>
  )
}
