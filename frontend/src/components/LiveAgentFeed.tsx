import React, { useEffect, useRef } from 'react'
import { useScanLive, type LiveEvent, type Finding } from '@/lib/api'
import { severityColor } from '@/lib/utils'
import { ACCENT, SUCCESS, WARN, SEVERITY_COLOR } from '@/lib/theme'
import { Activity, Cpu, CheckCircle2, AlertCircle, Zap, BrainCircuit } from 'lucide-react'

interface LiveAgentFeedProps {
  scanId: string
  onNewFinding?: (f: Finding) => void
  onScanComplete?: () => void
}

function EventLine({ event }: { event: LiveEvent }) {
  const ts = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString('en-US', { hour12: false })
    : new Date().toLocaleTimeString('en-US', { hour12: false })

  const getContent = () => {
    switch (event.type) {
      case 'agent_reasoning':
        return (
          <div className="flex items-start gap-2">
            <BrainCircuit size={13} className="mt-0.5 shrink-0" style={{ color: '#8b5cf6' }} />
            <span style={{ color: '#c4b5fd' }}>{event.reasoning}</span>
          </div>
        )
      case 'tool_started':
        return (
          <div className="flex items-center gap-2">
            <Cpu size={13} className="shrink-0" style={{ color: ACCENT }} />
            <span style={{ color: '#67e8f9' }}>
              Running <span className="font-mono font-semibold" style={{ color: ACCENT }}>{event.tool}</span>
              {event.budget_remaining !== undefined && (
                <span style={{ color: '#4b5563' }}> · {event.budget_remaining} budget left</span>
              )}
            </span>
            <span className="spin" style={{ color: ACCENT, fontSize: 10 }}>⊙</span>
          </div>
        )
      case 'tool_complete':
        return (
          <div className="flex items-center gap-2">
            <CheckCircle2 size={13} className="shrink-0" style={{ color: SUCCESS }} />
            <span style={{ color: '#6ee7b7' }}>
              <span className="font-mono font-semibold">{event.tool}</span> complete
              {event.metadata && typeof event.metadata.new_findings_count === 'number' && (
                <span style={{ color: '#4b5563' }}> · {event.metadata.new_findings_count as number} findings</span>
              )}
            </span>
          </div>
        )
      case 'finding': {
        if (!event.finding) return null
        const sev = event.finding.severity
        return (
          <div className="flex items-start gap-2 finding-flash rounded px-1">
            <AlertCircle size={13} className="mt-0.5 shrink-0" style={{ color: severityColor(sev) }} />
            <span>
              <span
                className="font-semibold font-mono text-xs px-1.5 py-0.5 rounded"
                style={{ background: `${severityColor(sev)}20`, color: severityColor(sev) }}
              >
                {sev.toUpperCase()}
              </span>
              <span style={{ color: '#e5e7eb' }} className="ml-2">{event.finding.title}</span>
              <span style={{ color: '#4b5563' }} className="ml-1">via {event.finding.source_tool}</span>
            </span>
          </div>
        )
      }
      case 'orchestration_complete':
      case 'scan_complete':
        return (
          <div className="flex items-center gap-2">
            <Zap size={13} className="shrink-0" style={{ color: WARN }} />
            <span style={{ color: '#fcd34d' }} className="font-semibold">
              Scan complete — handing off to Analyst Agent
            </span>
          </div>
        )
      case 'analyst_started':
        return (
          <div className="flex items-center gap-2">
            <BrainCircuit size={13} style={{ color: '#8b5cf6' }} />
            <span style={{ color: '#c4b5fd' }}>
              Analyst Agent starting — processing {event.findings_count ?? '?'} findings
            </span>
          </div>
        )
      case 'analyst_complete':
        return (
          <div className="flex items-center gap-2">
            <CheckCircle2 size={13} style={{ color: SUCCESS }} />
            <span style={{ color: '#6ee7b7' }}>
              Analysis complete — risk score: <strong>{event.risk_score}</strong>
            </span>
          </div>
        )
      case 'report_ready':
        return (
          <div className="flex items-center gap-2">
            <CheckCircle2 size={13} style={{ color: SUCCESS }} />
            <span style={{ color: '#6ee7b7' }} className="font-semibold">Report ready ✓</span>
          </div>
        )
      case 'exit_condition':
        return (
          <div className="flex items-center gap-2">
            <Activity size={13} style={{ color: WARN }} />
            <span style={{ color: '#fde68a' }}>{event.reasoning}</span>
          </div>
        )
      case 'scan_failed':
        return (
          <div className="flex items-center gap-2">
            <AlertCircle size={13} style={{ color: SEVERITY_COLOR.critical }} />
            <span style={{ color: '#fca5a5' }}>Scan failed: {event.error}</span>
          </div>
        )
      default:
        return (
          <span style={{ color: '#6b7280' }}>
            {event.type}: {event.reasoning ?? JSON.stringify(event.metadata ?? {})}
          </span>
        )
    }
  }

  const content = getContent()
  if (!content) return null

  return (
    <div className="feed-entry flex gap-3 py-1.5 text-xs leading-relaxed">
      <span className="font-mono shrink-0 select-none" style={{ color: '#374151', minWidth: 64 }}>
        {ts}
      </span>
      <div className="flex-1 min-w-0">{content}</div>
    </div>
  )
}

export default function LiveAgentFeed({ scanId, onNewFinding, onScanComplete }: LiveAgentFeedProps) {
  const feedRef = useRef<HTMLDivElement>(null)
  const hoveredRef = useRef(false)

  const { events, connected, findingsCount } = useScanLive(scanId, (event) => {
    if (event.type === 'finding' && event.finding) {
      onNewFinding?.(event.finding)
    }
    if (event.type === 'report_ready' || event.type === 'stream_end') {
      onScanComplete?.()
    }
  })

  useEffect(() => {
    if (!feedRef.current || hoveredRef.current) return
    feedRef.current.scrollTop = feedRef.current.scrollHeight
  }, [events])

  return (
    <div className="flex flex-col" style={{ height: '100%' }}>
      <div
        className="flex items-center justify-between px-4 py-2.5 shrink-0"
        style={{ borderBottom: '1px solid #1f2937' }}
      >
        <div className="flex items-center gap-2">
          <Activity size={14} style={{ color: ACCENT }} />
          <span className="text-xs font-semibold" style={{ color: '#9ca3af' }}>AGENT FEED</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono" style={{ color: '#6b7280' }}>{findingsCount} findings</span>
          <div className="flex items-center gap-1.5">
            <div
              className={connected ? 'pulse-dot' : ''}
              style={{ width: 7, height: 7, borderRadius: '50%', background: connected ? ACCENT : '#4b5563' }}
            />
            <span className="text-xs" style={{ color: connected ? ACCENT : '#4b5563' }}>
              {connected ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      <div
        ref={feedRef}
        className="flex-1 overflow-y-auto px-4 py-3"
        style={{ background: 'rgba(0,0,0,0.3)' }}
        onMouseEnter={() => { hoveredRef.current = true }}
        onMouseLeave={() => { hoveredRef.current = false }}
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3" style={{ color: '#374151' }}>
            <Activity size={28} />
            <p className="text-xs">Waiting for agent events…</p>
          </div>
        ) : (
          <div>
            {events.map((e, i) => (
              <div key={i} style={{ borderBottom: '1px solid rgba(31,41,55,0.4)' }}>
                <EventLine event={e} />
              </div>
            ))}
            {connected && (
              <div className="py-1.5 text-xs typewriter-cursor" style={{ color: '#374151' }}>
                Agent running
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
