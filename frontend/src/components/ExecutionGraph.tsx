import React, { useState, useCallback, useEffect } from 'react'
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  NodeTypes,
  Handle,
  Position,
  MarkerType,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { GitFork } from 'lucide-react'
import { severityColor, COLOR } from '../lib/theme'
import type { Finding } from '../lib/api'

// ── Tool node ────────────────────────────────────────────────────────────

function ToolNode({ data }: { data: Record<string, unknown> }) {
  const ms = data.duration_ms as number | undefined
  return (
    <div style={{
      background: COLOR.bg.surface,
      color: COLOR.text.primary,
      padding: '8px 16px',
      borderRadius: 8,
      fontSize: 12,
      fontWeight: 600,
      border: `2px solid ${COLOR.green['500']}`,
      minWidth: 130,
      textAlign: 'center',
      fontFamily: '"JetBrains Mono", monospace',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: COLOR.green['500'] }} />
      <div style={{ fontSize: 9, opacity: 0.5, marginBottom: 3, letterSpacing: '0.1em', textTransform: 'uppercase' }}>TOOL</div>
      <div>{String(data.tool_name ?? data.label ?? 'Tool')}</div>
      {ms !== undefined && (
        <div style={{ fontSize: 9, opacity: 0.45, marginTop: 3 }}>{ms}ms</div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: COLOR.green['500'] }} />
    </div>
  )
}

// ── Finding node ─────────────────────────────────────────────────────────

function FindingNode({ data }: { data: Record<string, unknown> }) {
  const sev    = String(data.severity ?? 'info').toLowerCase()
  const color  = severityColor(sev)
  const isKev  = Boolean(data.known_exploited)

  return (
    <div
      className={isKev ? 'kev-pulse' : ''}
      style={{
        background: `${color}12`,
        color: COLOR.text.primary,
        padding: '8px 14px',
        borderRadius: 8,
        fontSize: 11,
        border: `2px solid ${color}`,
        minWidth: 150,
        maxWidth: 210,
        position: 'relative',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: color }} />
      {isKev && (
        <div style={{
          position: 'absolute', top: -9, right: -9,
          background: COLOR.warn, color: COLOR.bg.base,
          fontSize: 8, fontWeight: 800, padding: '1px 5px', borderRadius: 4,
        }}>
          ⚡KEV
        </div>
      )}
      <div style={{ fontSize: 9, fontWeight: 700, color, textTransform: 'uppercase', marginBottom: 3, letterSpacing: '0.08em' }}>
        {sev}
      </div>
      <div style={{ fontSize: 11, lineHeight: 1.35 }}>
        {String(data.title ?? data.label ?? 'Finding').slice(0, 65)}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: color }} />
    </div>
  )
}

// ── Hypothesis / PTT node ─────────────────────────────────────────────────

function HypothesisNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div style={{
      background: 'transparent',
      color: COLOR.slate['200'],
      padding: '8px 14px',
      borderRadius: 8,
      fontSize: 11,
      border: `2px dashed ${COLOR.slate['500']}`,
      minWidth: 140,
      textAlign: 'center',
      fontStyle: 'italic',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: COLOR.slate['400'] }} />
      <div style={{ fontSize: 9, opacity: 0.5, marginBottom: 3, textTransform: 'uppercase' }}>HYPOTHESIS</div>
      <div>{String(data.label ?? 'Hypothesis').slice(0, 60)}</div>
      <Handle type="source" position={Position.Bottom} style={{ background: COLOR.slate['400'] }} />
    </div>
  )
}

const NODE_TYPES: NodeTypes = {
  tool_execution: ToolNode,
  finding:        FindingNode,
  hypothesis:     HypothesisNode,
  tool_run:       ToolNode,
}

// ── Side panel ────────────────────────────────────────────────────────────

function NodeDetail({ node, onClose }: { node: Node; onClose: () => void }) {
  const d = node.data as Record<string, unknown>

  return (
    <div style={{
      position: 'absolute', right: 0, top: 0, bottom: 0,
      width: 280, background: COLOR.bg.raised,
      borderLeft: `1px solid ${COLOR.bg.border}`,
      padding: 16, overflowY: 'auto', zIndex: 10, fontSize: 12,
    }}>
      <div className="flex justify-between items-center mb-3">
        <span className="font-semibold text-xs uppercase tracking-wider" style={{ color: COLOR.text.secondary }}>
          {node.type === 'tool_execution' ? 'Tool' : node.type === 'finding' ? 'Finding' : 'Node'} Detail
        </span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: COLOR.text.muted, cursor: 'pointer', fontSize: 16 }}>×</button>
      </div>
      {Object.entries(d)
        .filter(([, v]) => v !== undefined && v !== null && String(v).length > 0)
        .map(([k, v]) => (
          <div key={k} className="mb-2.5">
            <div style={{ color: COLOR.text.muted, fontSize: 9, textTransform: 'uppercase', marginBottom: 2, letterSpacing: '0.08em' }}>
              {k.replace(/_/g, ' ')}
            </div>
            <div style={{ color: COLOR.text.secondary, wordBreak: 'break-word' }}>{String(v)}</div>
          </div>
        ))}
    </div>
  )
}

// ── Layout helpers ────────────────────────────────────────────────────────

interface RawNode { id: string; type: string; data: Record<string, unknown> }
interface RawEdge { id: string; source: string; target: string; relationship?: string }

function layoutNodes(raw: RawNode[]): Node[] {
  const tools    = raw.filter(n => n.type === 'tool_execution' || n.type === 'tool_run')
  const findings = raw.filter(n => n.type === 'finding')
  const others   = raw.filter(n => !tools.includes(n) && !findings.includes(n))
  const out: Node[] = []
  tools.forEach((n, i)    => out.push({ id: n.id, type: n.type, data: n.data, position: { x: i * 230, y: 0 } }))
  findings.forEach((n, i) => out.push({ id: n.id, type: n.type, data: n.data, position: { x: i * 210, y: 200 } }))
  others.forEach((n, i)   => out.push({ id: n.id, type: n.type, data: n.data, position: { x: i * 200, y: 400 } }))
  return out
}

function layoutEdges(raw: RawEdge[]): Edge[] {
  return raw.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    animated: false,
    label: e.relationship ?? '',
    labelStyle: { fill: COLOR.text.muted, fontSize: 9, fontFamily: 'Inter, sans-serif' },
    labelBgStyle: { fill: COLOR.bg.base, fillOpacity: 0.85 },
    style: { stroke: COLOR.bg.border, strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: COLOR.bg.border, width: 12, height: 12 },
  }))
}

// ── Main component ────────────────────────────────────────────────────────

interface GraphData {
  nodes: RawNode[]
  edges: RawEdge[]
}

interface Props {
  graphData?: GraphData | null
  liveNodes?: RawNode[]
  liveEdges?: RawEdge[]
  isRunning?: boolean
  onFindingClick?: (finding: Finding) => void
}

export default function ExecutionGraph({
  graphData, liveNodes = [], liveEdges = [], isRunning, onFindingClick,
}: Props) {
  const [selected, setSelected] = useState<Node | null>(null)

  const mergedNodes = graphData
    ? [...graphData.nodes, ...liveNodes.filter(ln => !graphData.nodes.find(n => n.id === ln.id))]
    : liveNodes
  const mergedEdges = graphData
    ? [...graphData.edges, ...liveEdges.filter(le => !graphData.edges.find(e => e.id === le.id))]
    : liveEdges

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutNodes(mergedNodes))
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutEdges(mergedEdges))

  useEffect(() => {
    setNodes(layoutNodes(mergedNodes))
    setEdges(layoutEdges(mergedEdges))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mergedNodes.length, mergedEdges.length])

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    if (node.type === 'finding' && onFindingClick) {
      const d = node.data as Record<string, unknown>
      onFindingClick(d as unknown as Finding)
    } else {
      setSelected(prev => prev?.id === node.id ? null : node)
    }
  }, [onFindingClick])

  if (mergedNodes.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', height: 380, color: COLOR.text.muted,
        border: `1px solid ${COLOR.bg.border}`, borderRadius: 10, gap: 12, fontSize: 13,
      }}>
        <GitFork size={26} style={{ opacity: 0.35 }} />
        <p>{isRunning ? 'Building execution graph…' : 'Execution graph available for active scans'}</p>
      </div>
    )
  }

  return (
    <div style={{ height: 480, border: `1px solid ${COLOR.bg.border}`, borderRadius: 10, position: 'relative' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={NODE_TYPES}
        fitView
        style={{ background: COLOR.bg.base, borderRadius: 10 }}
      >
        <Background color={COLOR.bg.border} gap={24} />
        <Controls style={{ background: COLOR.bg.surface, border: `1px solid ${COLOR.bg.border}` }} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'tool_execution' || n.type === 'tool_run') return COLOR.green['700']
            const sev = String((n.data as Record<string, unknown>).severity ?? 'info').toLowerCase()
            return severityColor(sev)
          }}
          style={{ background: COLOR.bg.surface, border: `1px solid ${COLOR.bg.border}` }}
        />
      </ReactFlow>
      {selected && !onFindingClick && (
        <NodeDetail node={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
