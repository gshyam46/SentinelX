import React, { useEffect, useRef } from 'react'
import { riskColor, COLOR } from '../lib/theme'

interface Props {
  score: number
  size?: number
  animated?: boolean
}

function scoreLabel(s: number): string {
  if (s <= 30) return 'Safe'
  if (s <= 60) return 'Moderate'
  if (s <= 80) return 'High Risk'
  return 'Critical'
}

export default function RiskGauge({ score, size = 140, animated = true }: Props) {
  const clamped    = Math.max(0, Math.min(100, score))
  const prevScore  = useRef(0)
  const frameRef   = useRef<number | null>(null)
  const arcRef     = useRef<SVGPathElement | null>(null)
  const textRef    = useRef<SVGTextElement | null>(null)

  const cx = size / 2
  const cy = size / 2
  const r  = size * 0.38
  const sw = size * 0.065
  const tw = sw * 0.5

  const START = 210
  const SWEEP = 240

  function polarToXY(angle: number, radius: number) {
    const rad = ((angle - 90) * Math.PI) / 180
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) }
  }

  function buildArc(s: number) {
    const frac   = s / 100
    const end    = START + SWEEP * frac
    const p0     = polarToXY(START, r)
    const p1     = polarToXY(end, r)
    const large  = SWEEP * frac > 180 ? 1 : 0
    if (frac === 0) return `M ${p0.x} ${p0.y}`
    return `M ${p0.x} ${p0.y} A ${r} ${r} 0 ${large} 1 ${p1.x} ${p1.y}`
  }

  function trackArc() {
    const p0 = polarToXY(START, r)
    const p1 = polarToXY(START + SWEEP, r)
    return `M ${p0.x} ${p0.y} A ${r} ${r} 0 1 1 ${p1.x} ${p1.y}`
  }

  useEffect(() => {
    if (!animated) { prevScore.current = clamped; return }
    const from = prevScore.current
    const to   = clamped
    const dur  = 800
    const t0   = performance.now()

    const tick = (now: number) => {
      const prog   = Math.min((now - t0) / dur, 1)
      const eased  = 1 - Math.pow(1 - prog, 3)
      const cur    = from + (to - from) * eased
      const col    = riskColor(cur)

      if (arcRef.current) {
        arcRef.current.setAttribute('d', buildArc(cur))
        arcRef.current.setAttribute('stroke', col)
      }
      if (textRef.current) {
        textRef.current.textContent = Math.round(cur).toString()
        textRef.current.setAttribute('fill', col)
      }

      if (prog < 1) {
        frameRef.current = requestAnimationFrame(tick)
      } else {
        prevScore.current = to
      }
    }

    if (frameRef.current) cancelAnimationFrame(frameRef.current)
    frameRef.current = requestAnimationFrame(tick)
    return () => { if (frameRef.current) cancelAnimationFrame(frameRef.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clamped, animated])

  const color = riskColor(clamped)
  const label = scoreLabel(clamped)

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size * 0.88} viewBox={`0 0 ${size} ${size}`}>
        {/* Track */}
        <path d={trackArc()} fill="none" stroke={COLOR.bg.border} strokeWidth={tw} strokeLinecap="round" />

        <defs>
          <filter id="gauge-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Arc */}
        <path
          ref={arcRef}
          d={buildArc(animated ? prevScore.current : clamped)}
          fill="none"
          stroke={color}
          strokeWidth={sw}
          strokeLinecap="round"
          filter="url(#gauge-glow)"
        />

        {/* Score */}
        <text
          ref={textRef}
          x={cx}
          y={cy + size * 0.06}
          textAnchor="middle"
          fill={color}
          fontSize={size * 0.22}
          fontWeight="700"
          fontFamily="Inter, sans-serif"
        >
          {animated ? prevScore.current : clamped}
        </text>
        <text
          x={cx}
          y={cy + size * 0.22}
          textAnchor="middle"
          fill={COLOR.text.muted}
          fontSize={size * 0.09}
          fontFamily="Inter, sans-serif"
        >
          / 100
        </text>
      </svg>
      <div
        className="text-xs font-semibold tracking-widest uppercase mt-1"
        style={{ color, letterSpacing: '0.12em' }}
      >
        {label}
      </div>
    </div>
  )
}
