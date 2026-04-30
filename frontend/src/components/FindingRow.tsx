import React from 'react'
import { type Finding } from '../lib/api'
import { severityColor } from '../lib/utils'
import { Lock, CheckCircle2, XCircle, Clock } from 'lucide-react'
import { WARN } from '../lib/theme'

interface FindingRowProps {
  finding: Finding
  index: number
  gated?: boolean
  isNew?: boolean
  isKev?: boolean
  onSelect?: (f: Finding) => void
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity.toUpperCase()}</span>
}

function OWASPTag({ cat }: { cat: string }) {
  return (
    <span
      className="inline-flex items-center text-xs px-1.5 py-0.5 rounded font-mono"
      style={{ background: 'rgba(0,212,255,0.06)', color: '#67e8f9', border: '1px solid rgba(0,212,255,0.15)' }}
    >
      {cat}
    </span>
  )
}

function ValidatedBadge({ validated }: { validated: Finding['validated'] }) {
  if (validated === 'confirmed') {
    return <CheckCircle2 size={14} style={{ color: '#10b981' }} title="Confirmed" />
  }
  if (validated === 'false_positive') {
    return <XCircle size={14} style={{ color: '#6b7280' }} title="False positive" />
  }
  return <Clock size={14} style={{ color: '#4b5563' }} title="Pending validation" />
}

export default function FindingRow({ finding, index, gated, isNew, isKev, onSelect }: FindingRowProps) {
  const sev = finding.severity
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
              <SeverityBadge severity={sev} />
              <span className="text-sm font-mono" style={{ color: '#9ca3af' }}>{finding.title}</span>
              {finding.owasp_categories.map(c => <OWASPTag key={c} cat={c} />)}
            </div>
            <div
              className="absolute inset-0 flex items-center justify-center gap-2 rounded"
              style={{ background: 'rgba(10,14,26,0.6)' }}
            >
              <Lock size={14} style={{ color: '#9ca3af' }} />
              <span className="text-xs" style={{ color: '#9ca3af' }}>Upgrade to unlock</span>
            </div>
          </div>
        </td>
      </tr>
    )
  }

  return (
    <tr
      className={isNew ? 'finding-flash' : ''}
      onClick={() => onSelect?.(finding)}
      style={{ borderLeft: `3px solid ${borderColor}60` }}
      data-index={index}
    >
      {/* Severity */}
      <td><SeverityBadge severity={sev} /></td>

      {/* Title + KEV tag */}
      <td>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm" style={{ color: '#f9fafb' }}>
            {finding.title}
          </span>
          {isKev && (
            <span
              className="text-xs px-1.5 py-0.5 rounded font-bold"
              style={{ background: 'rgba(245,158,11,0.15)', color: WARN, border: `1px solid rgba(245,158,11,0.3)` }}
            >
              ⚡ KEV
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

      {/* CVE */}
      <td>
        {finding.cve_id ? (
          <span className="font-mono text-xs" style={{ color: '#fca5a5' }}>
            {finding.cve_id}
          </span>
        ) : (
          <span style={{ color: '#374151' }}>—</span>
        )}
      </td>

      {/* Validated */}
      <td>
        <ValidatedBadge validated={finding.validated} />
      </td>

      {/* Tool source */}
      <td>
        <span className="font-mono text-xs" style={{ color: '#6b7280' }}>
          {finding.source_tool}
        </span>
      </td>
    </tr>
  )
}
