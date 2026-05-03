/**
 * SentinelX API Client
 * Fully typed client matching backend Pydantic schemas.
 * Includes useScanLive() WebSocket hook with auto-reconnect.
 */
import axios from 'axios'
import { useEffect, useRef, useState, useCallback } from 'react'

// ─── Types ────────────────────────────────────────────────────────────

export type ScanType = 'passive' | 'active' | 'full'
export type ScanStatus = 'pending' | 'running' | 'complete' | 'failed'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  title: string
  severity: Severity
  description: string
  target: string
  source_tool: string
  owasp_categories: string[]
  cve_id?: string
  remediation?: string
  discovered_at: string
  validated?: 'confirmed' | 'false_positive' | 'pending' | null
  known_exploited?: boolean
  confidence?: number
  fix_status?: 'fixed' | 'still_present' | null
}

export interface AuthConfig {
  type: 'cookie' | 'bearer' | 'basic'
  cookie?: string
  token?: string
  username?: string
  password?: string
  login_url?: string
}

// ─── LLM Security types ───────────────────────────────────────────────

export interface LLMCheck {
  check_id: string
  title: string
  detected: boolean
  confidence: number
  evidence: string[]
  description?: string
}

export interface LLMSecurityReport {
  scan_id: string
  generated_at: string
  risk_score: number
  checks: LLMCheck[]
  attack_chains: AttackChain[]
  summary?: string
}

// ─── User / Auth types ────────────────────────────────────────────────

export interface UserProfile {
  id: string
  email: string
  full_name: string | null
  tier: string
  scan_count: number
  is_active: boolean
  created_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  user: UserProfile
}

// ─── Scan types ───────────────────────────────────────────────────────

export interface ScanStatusResponse {
  id: string
  domain: string
  scan_type: ScanType
  status: ScanStatus
  progress: number
  current_step?: string
  created_at: string
  completed_at?: string
  risk_score: number
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  scan_mode?: 'deterministic' | 'adaptive'
}

export interface ExecutionGraphNode {
  id: string
  type: 'tool_execution' | 'finding'
  data: Record<string, unknown>
}

export interface ExecutionGraphEdge {
  id: string
  source: string
  target: string
  relationship?: string
}

export interface ExecutionGraph {
  nodes: ExecutionGraphNode[]
  edges: ExecutionGraphEdge[]
}

export interface ScanResultResponse extends ScanStatusResponse {
  results?: {
    findings?: Finding[]
    tools_run?: string[]
    ai_report?: AnalysisReport
    scan_metadata?: Record<string, unknown>
    gated?: boolean
    hidden_findings_count?: number
    upgrade_message?: string
    report_ready?: boolean
  }
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  risk_score: number
  error_message?: string
  execution_graph?: ExecutionGraph | null
  execution_graph_present?: boolean
  kev_matches?: string[]
}

export interface ScanListResponse {
  scans: ScanStatusResponse[]
  total: number
}

export interface ScanProgressResponse {
  scan_id: string
  status: ScanStatus
  progress: number
  current_step?: string
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  budget_remaining?: number
  tools_run: string[]
  owasp_coverage: string[]
}

export interface AnalysisReport {
  scan_id: string
  generated_at: string
  executive_summary: string
  risk_score: number
  attack_chains: AttackChain[]
  owasp_coverage: Record<string, string>
  critical_findings: string[]
  remediation_priorities: RemediationItem[]
  follow_up_tools?: string[]
  analyst_notes?: string
  model_used?: string
}

export interface AttackChain {
  name: string
  steps: string[]
  impact: 'high' | 'medium' | 'low'
}

export interface RemediationItem {
  priority: number
  finding: string
  action: string
  effort: 'low' | 'medium' | 'high'
}

export interface ScanCreateRequest {
  domain: string
  scan_type: ScanType
  scan_mode?: 'deterministic' | 'adaptive'
  authorization_confirmed: boolean
  auth_config?: AuthConfig
}

// ─── Live event types (Redis pub/sub via WebSocket) ───────────────────

export type LiveEventType =
  | 'tool_started'
  | 'tool_complete'
  | 'finding'
  | 'findings_count'
  | 'agent_reasoning'
  | 'exit_condition'
  | 'scan_complete'
  | 'orchestration_complete'
  | 'analyst_started'
  | 'analyst_complete'
  | 'analyst_followup'
  | 'mini_scan_started'
  | 'mini_scan_complete'
  | 'report_ready'
  | 'scan_failed'
  | 'stream_end'
  | 'scan_snapshot'
  | 'error'

export interface LiveEvent {
  type: LiveEventType
  timestamp?: string
  tool?: string
  finding?: Finding
  reasoning?: string
  budget_remaining?: number
  metadata?: Record<string, unknown>
  findings_count?: number
  latest_severity?: Severity
  risk_score?: number
  error?: string
  status?: ScanStatus
  scan_id?: string
  owasp_coverage?: string[]
}

// ─── Axios instance ───────────────────────────────────────────────────

const http = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '/api/v1',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT from localStorage
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Attach dev tier-bypass header automatically (only when env var is set)
const DEV_BYPASS_SECRET = import.meta.env.VITE_DEV_BYPASS_SECRET
http.interceptors.request.use((config) => {
  if (DEV_BYPASS_SECRET) config.headers['X-Dev-Bypass'] = DEV_BYPASS_SECRET
  return config
})

// ─── API methods ──────────────────────────────────────────────────────

export const api = {
  // Auth
  async login(email: string, password: string): Promise<TokenResponse> {
    const res = await http.post<TokenResponse>('/auth/login', { email, password })
    localStorage.setItem('sentinel_token', res.data.access_token)
    localStorage.setItem('sentinel_user', JSON.stringify(res.data.user))
    return res.data
  },

  logout() {
    localStorage.removeItem('sentinel_token')
    localStorage.removeItem('sentinel_user')
  },

  // Scans
  async createScan(payload: ScanCreateRequest): Promise<ScanStatusResponse> {
    const res = await http.post<ScanStatusResponse>('/scans', payload)
    return res.data
  },

  async listScans(skip = 0, limit = 20): Promise<ScanListResponse> {
    const res = await http.get<ScanListResponse>('/scans', { params: { skip, limit } })
    return res.data
  },

  async getScan(id: string): Promise<ScanResultResponse> {
    const res = await http.get<ScanResultResponse>(`/scans/${id}`)
    return res.data
  },

  async getScanProgress(id: string): Promise<ScanProgressResponse> {
    const res = await http.get<ScanProgressResponse>(`/scans/${id}/progress`)
    return res.data
  },

  async getScanReport(id: string): Promise<AnalysisReport> {
    const res = await http.get<AnalysisReport>(`/scans/${id}/report`)
    return res.data
  },

  async downloadScanPdf(id: string): Promise<Blob> {
    const res = await http.get(`/scans/${id}/pdf-report`, { responseType: 'blob' })
    return res.data as Blob
  },

  async register(email: string, password: string, fullName?: string): Promise<TokenResponse> {
    const res = await http.post<TokenResponse>('/auth/register', {
      email,
      password,
      full_name: fullName ?? null,
    })
    localStorage.setItem('sentinel_token', res.data.access_token)
    localStorage.setItem('sentinel_user', JSON.stringify(res.data.user))
    return res.data
  },

  async getLLMSecurityReport(scanId: string): Promise<LLMSecurityReport> {
    const res = await http.get<LLMSecurityReport>(`/scans/${scanId}/llm-security-report`)
    return res.data
  },

  // Health
  async health() {
    const res = await http.get('/health')
    return res.data
  },
}

// ─── useScanLive — WebSocket hook ─────────────────────────────────────

export interface UseScanLiveReturn {
  events: LiveEvent[]
  connected: boolean
  latestFinding: Finding | null
  toolsInProgress: Set<string>
  findingsCount: number
}

export function useScanLive(
  scanId: string | null,
  onEvent?: (e: LiveEvent) => void
): UseScanLiveReturn {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [latestFinding, setLatestFinding] = useState<Finding | null>(null)
  const [toolsInProgress, setToolsInProgress] = useState<Set<string>>(new Set())
  const [findingsCount, setFindingsCount] = useState(0)

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isMounted = useRef(true)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  const connect = useCallback(() => {
    if (!scanId || !isMounted.current) return

    const token = localStorage.getItem('sentinel_token') ?? ''
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host = window.location.host
    // Token passed as query param — browsers cannot send Authorization headers on WS
    const url = `${protocol}://${host}/api/v1/scans/${scanId}/live?token=${encodeURIComponent(token)}`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      if (isMounted.current) setConnected(true)
    }

    ws.onmessage = (msg) => {
      if (!isMounted.current) return
      try {
        const event: LiveEvent = JSON.parse(msg.data as string)
        setEvents((prev) => [...prev, event])
        onEventRef.current?.(event)

        if (event.type === 'tool_started' && event.tool) {
          setToolsInProgress((s) => new Set(s).add(event.tool!))
        }
        if (event.type === 'tool_complete' && event.tool) {
          setToolsInProgress((s) => {
            const next = new Set(s); next.delete(event.tool!); return next
          })
        }
        if (event.type === 'finding' && event.finding) {
          setLatestFinding(event.finding)
          setFindingsCount((c) => c + 1)
        }
        if (event.type === 'findings_count' && event.findings_count !== undefined) {
          setFindingsCount(event.findings_count)
        }
        if (event.type === 'stream_end') {
          ws.close()
        }
      } catch {
        // non-JSON message — ignore
      }
    }

    ws.onclose = () => {
      if (!isMounted.current) return
      setConnected(false)
      // Auto-reconnect after 3s unless stream ended gracefully
      reconnectRef.current = setTimeout(() => {
        if (isMounted.current) connect()
      }, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [scanId])

  useEffect(() => {
    isMounted.current = true
    connect()
    return () => {
      isMounted.current = false
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { events, connected, latestFinding, toolsInProgress, findingsCount }
}
