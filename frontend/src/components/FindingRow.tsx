import React, { useState } from 'react'
import { type Finding } from '@/lib/api'
import { severityColor } from '@/lib/utils'
import {
  ChevronDown, ChevronRight, Lock, ExternalLink,
  ShieldAlert, Wrench, Link2, BookOpen,
} from 'lucide-react'

interface FindingRowProps {
  finding: Finding
  index: number
  gated?: boolean
  isNew?: boolean
}

const OWASP_NAMES: Record<string, string> = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable & Outdated Components',
  A07: 'Identification & Auth Failures',
  A08: 'Software & Data Integrity Failures',
  A09: 'Security Logging & Monitoring Failures',
  A10: 'Server-Side Request Forgery',
}

const EXPLOITABILITY: Record<string, { label: string; color: string; score: number }> = {
  critical: { label: 'Trivial',    color: '#EF4444', score: 9 },
  high:     { label: 'Easy',      color: '#F97316', score: 7 },
  medium:   { label: 'Moderate',  color: '#EAB308', score: 5 },
  low:      { label: 'Difficult', color: '#3B82F6', score: 3 },
  info:     { label: 'N/A',       color: '#6B7280', score: 1 },
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge badge-${severity}`}>
      {severity.toUpperCase()}
    </span>
  )
}

function OWASPTag({ cat }: { cat: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded font-mono"
      style={{ background: 'rgba(59,130,246,0.08)', color: '#60A5FA', border: '1px solid rgba(59,130,246,0.2)' }}
      title={OWASP_NAMES[cat] ?? cat}
    >
      {cat}
    </span>
  )
}

export default function FindingRow({ finding, index, gated, isNew }: FindingRowProps) {
  const [expanded, setExpanded] = useState(false)
  const sev = finding.severity
  const exploit = EXPLOITABILITY[sev] ?? EXPLOITABILITY.info
  const borderColor = severityColor(sev)

  if (gated) {
    return (
      <tr>
        <td colSpan={6} style={{ padding: 0 }}>
          <div
            className="relative flex items-center gap-4 px-4 py-3"
            style={{ borderLeft: `3px solid ${borderColor}30`, background: 'rgba(0,0,0,0.2)' }}
          >
            <div className="gated-blur flex items-center gap-4 flex-1">
              <SeverityBadge severity={finding.severity} />
              <span className="text-sm font-mono" style={{ color: '#9CA3AF' }}>
                {finding.title}
              </span>
              {finding.owasp_categories.map(c => <OWASPTag key={c} cat={c} />)}
            </div>
            <div
              className="absolute inset-0 flex items-center justify-center gap-2 rounded"
              style={{ background: 'rgba(10,13,20,0.6)' }}
            >
              <Lock size={14} style={{ color: '#9CA3AF' }} />
              <span className="text-xs" style={{ color: '#9CA3AF' }}>
                Upgrade to unlock this finding
              </span>
            </div>
          </div>
        </td>
      </tr>
    )
  }

  return (
    <>
      <tr
        className={isNew ? 'finding-flash' : ''}
        onClick={() => setExpanded(!expanded)}
        style={{ borderLeft: `3px solid ${expanded ? borderColor : borderColor + '60'}` }}
      >
        {/* Severity */}
        <td>
          <SeverityBadge severity={sev} />
        </td>

        {/* Title */}
        <td>
          <div className="flex items-center gap-2">
            {expanded
              ? <ChevronDown size={13} style={{ color: '#6B7280', flexShrink: 0 }} />
              : <ChevronRight size={13} style={{ color: '#6B7280', flexShrink: 0 }} />
            }
            <span className="font-medium text-sm" style={{ color: '#F9FAFB' }}>
              {finding.title}
            </span>
            {finding.cve_id && (
              <span
                className="font-mono text-xs px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(239,68,68,0.1)', color: '#FCA5A5', border: '1px solid rgba(239,68,68,0.2)' }}
              >
                {finding.cve_id}
              </span>
            )}
          </div>
        </td>

        {/* OWASP */}
        <td>
          <div className="flex gap-1 flex-wrap">
            {finding.owasp_categories.slice(0, 2).map(c => <OWASPTag key={c} cat={c} />)}
          </div>
        </td>

        {/* Tool */}
        <td>
          <span className="font-mono text-xs" style={{ color: '#6B7280' }}>
            {finding.source_tool}
          </span>
        </td>

        {/* Target */}
        <td>
          <span
            className="font-mono text-xs truncate block max-w-48"
            style={{ color: '#9CA3AF' }}
            title={finding.target}
          >
            {finding.target}
          </span>
        </td>

        {/* Actions */}
        <td onClick={(e) => e.stopPropagation()}>
          <button
            className="p-1.5 rounded hover:bg-white/5 transition-colors"
            style={{ color: '#6B7280' }}
            title="Open target"
          >
            <ExternalLink size={13} />
          </button>
        </td>
      </tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr>
          <td colSpan={6} style={{ padding: 0, background: 'rgba(0,0,0,0.25)' }}>
            <div className="p-5 space-y-4">
              {/* Description + exploitability */}
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldAlert size={13} style={{ color: '#9CA3AF' }} />
                    <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6B7280' }}>
                      Description
                    </span>
                  </div>
                  <p className="text-sm leading-relaxed" style={{ color: '#D1D5DB' }}>
                    {finding.description}
                  </p>
                </div>

                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#6B7280' }}>
                      Exploitability
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span style={{ color: exploit.color }} className="font-semibold text-sm">
                        {exploit.label}
                      </span>
                      <span className="text-xs" style={{ color: '#4B5563' }}>{exploit.score}/10</span>
                    </div>
                    <div className="progress-bar w-full">
                      <div
                        className="progress-fill"
                        style={{ width: `${exploit.score * 10}%`, background: exploit.color }}
                      />
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {finding.owasp_categories.map(c => (
                        <span key={c} className="text-xs" style={{ color: '#60A5FA' }}>
                          <OWASPTag cat={c} /> <span style={{ color: '#6B7280', fontSize: 10 }}>{OWASP_NAMES[c]}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Business impact */}
              <div
                className="rounded-lg p-3"
                style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.12)' }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Link2 size={12} style={{ color: '#FCA5A5' }} />
                  <span className="text-xs font-semibold" style={{ color: '#FCA5A5' }}>Business Impact</span>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: '#D1D5DB' }}>
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
                <div
                  className="rounded-lg p-3"
                  style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.12)' }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <Wrench size={12} style={{ color: '#86EFAC' }} />
                    <span className="text-xs font-semibold" style={{ color: '#86EFAC' }}>Remediation Steps</span>
                  </div>
                  <p className="text-xs leading-relaxed font-mono" style={{ color: '#D1D5DB' }}>
                    {finding.remediation}
                  </p>
                </div>
              )}

              {/* References */}
              {finding.cve_id && (
                <div className="flex items-center gap-3">
                  <BookOpen size={12} style={{ color: '#6B7280' }} />
                  <span className="text-xs" style={{ color: '#6B7280' }}>References:</span>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs font-mono hover:underline"
                    style={{ color: '#60A5FA' }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {finding.cve_id} ↗
                  </a>
                </div>
              )}

              <div className="flex items-center gap-2 pt-1" style={{ borderTop: '1px solid #1F2937' }}>
                <span className="text-xs" style={{ color: '#4B5563' }}>
                  Discovered {new Date(finding.discovered_at).toLocaleString()} via{' '}
                  <span className="font-mono">{finding.source_tool}</span>
                </span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
