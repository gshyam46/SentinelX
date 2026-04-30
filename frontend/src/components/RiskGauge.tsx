import React, { useEffect, useRef } from 'react'
import { SUCCESS, WARN, DANGER } from '@/lib/theme'

interface RiskGaugeProps {
  score: number
  size?: number
  animated?: boolean
}

function scoreToColor(score: number): string {
  if (score <= 30) return SUCCESS
  if (score <= 60) return WARN
  if (score <= 80) return '#f97316'
  return DANGER
}

function scoreLabel(score: number): string {
  if (score <= 30) return 'Safe'
  if (score <= 60) return 'Moderate'
  if (score <= 80) return 'High Risk'
  return 'Critical'
}

export default function RiskGauge({ score, size = 140, animated = true }: RiskGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, score))
  const prevScore = useRef(0)
  const animFrameRef = useRef<number | null>(null)
  const arcRef = useRef<SVGPathElement | null>(null)
  const textRef = useRef<SVGTextElement | null>(null)

  const cx = size / 2
  const cy = size / 2
  const r = size * 0.38
  const strokeWidth = size * 0.065
  const trackWidth = strokeWidth * 0.5

  const startAngle = 210
  const sweepAngle = 240

  function polarToXY(angle: number, radius: number) {
    const rad = ((angle - 90) * Math.PI) / 180
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    }
  }

  function buildArc(s: number) {
    const fraction = s / 100
    const endAngle = startAngle + sweepAngle * fraction
    const start = polarToXY(startAngle, r)
    const end = polarToXY(endAngle, r)
    const largeArc = sweepAngle * fraction > 180 ? 1 : 0
    if (fraction === 0) return `M ${start.x} ${start.y}`
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`
  }

  function buildTrackArc() {
    const start = polarToXY(startAngle, r)
    const end = polarToXY(startAngle + sweepAngle, r)
    return `M ${start.x} ${start.y} A ${r} ${r} 0 1 1 ${end.x} ${end.y}`
  }

  useEffect(() => {
    if (!animated) {
      prevScore.current = clampedScore
      return
    }
    const from = prevScore.current
    const to = clampedScore
    const duration = 800
    const start = performance.now()

    const tick = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      const current = from + (to - from) * eased

      if (arcRef.current) {
        arcRef.current.setAttribute('d', buildArc(current))
        arcRef.current.setAttribute('stroke', scoreToColor(current))
      }
      if (textRef.current) {
        textRef.current.textContent = Math.round(current).toString()
        textRef.current.setAttribute('fill', scoreToColor(current))
      }

      if (progress < 1) {
        animFrameRef.current = requestAnimationFrame(tick)
      } else {
        prevScore.current = to
      }
    }

    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    animFrameRef.current = requestAnimationFrame(tick)
    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clampedScore, animated])

  const color = scoreToColor(clampedScore)
  const label = scoreLabel(clampedScore)

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size * 0.88} viewBox={`0 0 ${size} ${size}`}>
        <path
          d={buildTrackArc()}
          fill="none"
          stroke="#1f2937"
          strokeWidth={trackWidth}
          strokeLinecap="round"
        />
        <defs>
          <filter id="gauge-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path
          ref={arcRef}
          d={buildArc(animated ? prevScore.current : clampedScore)}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          filter="url(#gauge-glow)"
        />
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
          {animated ? prevScore.current : clampedScore}
        </text>
        <text
          x={cx}
          y={cy + size * 0.22}
          textAnchor="middle"
          fill="#4b5563"
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
