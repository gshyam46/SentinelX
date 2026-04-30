export const COLOR = {
  bg: {
    base:    '#080d0b',
    surface: '#0e1512',
    raised:  '#141f1a',
    border:  '#1e2e28',
    hover:   '#1a2820',
  },
  green: {
    '900': '#0a1f16',
    '700': '#0f3d26',
    '500': '#1a6b40',
    '400': '#228855',
    '300': '#2ea55f',
    glow:  'rgba(30,107,64,0.25)',
  },
  slate: {
    '600': '#2a3f4a',
    '500': '#3a5566',
    '400': '#4a6d82',
    '300': '#6b8fa6',
    '200': '#8faebf',
    glow:  'rgba(74,109,130,0.2)',
  },
  severity: {
    critical: '#e53b3b',
    high:     '#d4721a',
    medium:   '#c4962a',
    low:      '#2ea55f',
    info:     '#4a6d82',
  },
  text: {
    primary:   '#d4e8df',
    secondary: '#8faebf',
    muted:     '#4a6a5a',
    inverse:   '#080d0b',
  },
  accent:  '#2ea55f',
  danger:  '#e53b3b',
  warn:    '#c4962a',
  success: '#2ea55f',
} as const

export const FONT = {
  sans: '"Inter", "SF Pro Display", system-ui, sans-serif',
  mono: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
} as const

export function severityColor(sev: string): string {
  return (COLOR.severity as Record<string, string>)[sev] ?? COLOR.severity.info
}

export function riskColor(score: number): string {
  if (score <= 30) return COLOR.success
  if (score <= 60) return COLOR.warn
  return COLOR.danger
}

// Backward-compat flat exports for files not yet migrated to COLOR.*
export const SEVERITY_COLOR = COLOR.severity
export const BG             = COLOR.bg
export const ACCENT         = COLOR.accent
export const DANGER         = COLOR.danger
export const WARN           = COLOR.warn
export const SUCCESS        = COLOR.success
