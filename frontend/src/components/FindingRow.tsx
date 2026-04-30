import React from 'react'
import { type Finding } from '../lib/api'
import { severityColor, COLOR } from '../lib/theme'
import { Lock, CheckCircle2, XCircle, Clock } from 'lucide-react'

interface Props {
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
      className="inline-flex items-center text-xs px-1.5 py-0.5 rounded mono"
      style={{ background: 'rgba(74,109,130,0.08)', color: COLOR.slate['300'], border: `1px solid ${COLOR.slate['600']}` }}
    >
      {cat}
    </span>
  )
}

function ValidatedIcon({ validated }: { validated: Finding['validated'] }) {
  if (validated === 'confirmed')     return <CheckCircle2 size={13} style={{ color: COLOR.success }} title="Confirmed" />
  if (validated === 'false_positive') return <XCircle     size={13} style={{ color: COLOR.danger  }} title="False positive" />
  return <Clock size={13} style={{ color: COLOR.text.muted }} title="Pending" />
}

export default function FindingRow({ finding, index, gated, isNew, isKev, onSelect }: Props) {
  const sev  = finding.severity
  const col  = severityColor(sev)

  if (gated) {
    return (
      <tr>
        <td colSpan={6} style={{ padding: 0 }}>
          <div
            className="relative flex items-center gap-4 px-4 py-3"
            style={{ borderLeft: `3px solid ${col}25`, background: 'rgba(0,0,0,0.15)' }}
          >
            <div className="gated-blur flex items-center gap-4 flex-1">
              <SeverityBadge severity={sev} />
              <span className="text-sm mono" style={{ color: COLOR.text.muted }}>{finding.title}</span>
              {finding.owasp_categories.map(c => <OWASPTag key={c} cat={c} />)}
            </div>
            <div className="absolute inset-0 flex items-center justify-center gap-2 rounded">
              <Lock size={13} style={{ color: COLOR.text.muted }} />
              <span className="text-xs" style={{ color: COLOR.text.muted }}>Upgrade to unlock</span>
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
      style={{ borderLeft: `3px solid ${col}50` }}
      data-index={index}
    >
      <td><SeverityBadge severity={sev} /></td>

      <td>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm" style={{ color: COLOR.text.primary }}>{finding.title}</span>
          {isKev && (
            <span className="text-xs px-1.5 py-0.5 rounded font-bold" style={{ background: 'rgba(196,150,42,0.12)', color: COLOR.warn, border: '1px solid rgba(196,150,42,0.25)' }}>
              ⚡ KEV
            </span>
          )}
        </div>
      </td>

      <td>
        <div className="flex gap-1 flex-wrap">
          {finding.owasp_categories.slice(0, 2).map(c => <OWASPTag key={c} cat={c} />)}
        </div>
      </td>

      <td>
        {finding.cve_id
          ? <span className="mono text-xs" style={{ color: '#fca5a5' }}>{finding.cve_id}</span>
          : <span style={{ color: COLOR.text.muted }}>—</span>
        }
      </td>

      <td><ValidatedIcon validated={finding.validated} /></td>

      <td><span className="mono text-xs" style={{ color: COLOR.text.muted }}>{finding.source_tool}</span></td>
    </tr>
  )
}
