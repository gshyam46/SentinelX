import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function severityColor(sev: string): string {
  switch (sev) {
    case 'critical': return '#EF4444'
    case 'high':     return '#F97316'
    case 'medium':   return '#EAB308'
    case 'low':      return '#3B82F6'
    default:         return '#6B7280'
  }
}

export function riskClass(score: number): string {
  if (score <= 30) return 'risk-safe'
  if (score <= 60) return 'risk-moderate'
  if (score <= 80) return 'risk-high'
  return 'risk-critical'
}

export function riskColor(score: number): string {
  if (score <= 30) return '#22C55E'
  if (score <= 60) return '#EAB308'
  if (score <= 80) return '#F97316'
  return '#EF4444'
}

export function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'Just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}
