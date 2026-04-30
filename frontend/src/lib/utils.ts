import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { SEVERITY_COLOR, SUCCESS, WARN, DANGER } from './theme'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function severityColor(sev: string): string {
  return SEVERITY_COLOR[sev as keyof typeof SEVERITY_COLOR] ?? SEVERITY_COLOR.info
}

export function riskClass(score: number): string {
  if (score <= 30) return 'risk-safe'
  if (score <= 60) return 'risk-moderate'
  if (score <= 80) return 'risk-high'
  return 'risk-critical'
}

export function riskColor(score: number): string {
  if (score <= 30) return SUCCESS
  if (score <= 60) return WARN
  return DANGER
}

export function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'Just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}
