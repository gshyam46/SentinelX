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
import { SEVERITY_COLOR, BG, WARN } from '../lib/theme'
import { GitFork } from 'lucide-react'

const TOOL_BG = '#1e3a5f'
const TOOL_BORDER = '#2563eb'

// ── Custom node: Tool ─────────────────────────────────────────────────────────

function ToolNode({ data }: { data: Record<string, unknown> }) {
  const durationMs = data.duration_ms as number | undefined
  return (
    <div
      style={{
        background: TOOL_BG,
        color: '#e2e8f0',
        padding: '8px 16px',
        borderRadius: 10,
        fontSize: 12,
        fontWeight: 600,
        border: `2px solid ${TOOL_BORDER}`,
        minWidth: 130,
        textAlign: 'center',
        fontFamily: "'JetBrains Mono', monospace",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: TOOL_BORDER }} />
      <div style={{ fontSize: 9, opacity: 0.55, marginBottom: 3, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        TOOL
      </div>
      <div>{String(data.tool_name ?? data.label ?? 'Tool')}</div>
      {durationMs !== undefined && (
        <div style={{ fontSize: 9, opacity: 0.5, marginTop: 3, fontFamily: 'inherit' }}>
          {durationMs}ms
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: TOOL_BORDER }} />
    </div>
  )
}

// ── Custom node: Finding ──────────────────────────────────────────────────────

function FindingNode({ data }: { data: Record<string, unknown> }) {
  const sev = String(data.severity ?? 'info').toLowerCase()
  const color = SEVERITY_COLOR[sev as keyof typeof SEVERITY_COLOR] ?? SEVERITY_COLOR.info
  const isKev = Boolean(data.known_exploited)

  return (
    <div
      className={isKev ? 'kev-pulse' : ''}
      style={{
        background: `${color}18`,
        color: '#f9fafb',
        padding: '8px 14px',
        borderRadius: 10,
        fontSize: 11,
        border: `2px solid ${color}`,
        minWidth: 150,
        maxWidth: 210,
        position: 'relative',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: color }} />
      {isKev && (
        <div
          style={{
            position: 'absolute', top: -9, right: -9,
            background: WARN, color: '#0a0e1a',
            fontSize: 8, fontWeight: 800,
            padding: '1px 5px', borderRadius: 4,
            letterSpacing: '0.05em',
          }}
        >
          ⚡KEV
        </div>
      )}
      <div style={{ fontSize: 9, fontWeight: 700, color, textTransform: 'uppercase', marginBottom: 3, letterSpacing: '0.08em' }}>
        {sev}
      </div>
      <div style={{ fontSize: 11, lineHeight: 1.35, fontFamily: "'Inter', sans-serif" }}>
        {String(data.title ?? data.label ?? 'Finding').slice(0, 65)}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: color }} />
    </div>
  )
}

const NODE_TYPES: NodeTypes = {
  tool_execution: ToolNode,
  finding: FindingNode,
}

// ── Side panel ────────────────────────────────────────────────────────────────

function NodeDetail({ node, onClose }: { node: Node; onClose: () => void }) {
  const d = node.data as Record<string, unknown>
  const isToolNode = node.type === 'tool_execution'

  return (
    <div
      style={{
        position: 'absolute', right: 0, top: 0, bottom: 0,
        width: 300, background: BG.surface,
        borderLeft: `1px solid ${BG.border}`,
        padding: 20, overflowY: 'auto', zIndex: 10, fontSize: 12,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, alignItems: 'center' }}>
        <span style={{ fontWeight: 700, color: '#f9fafb', fontSize: 13 }}>
          {isToolNode ? 'Tool Detail' : 'Finding Detail'}
        </span>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: 18, lineHeight: 1 }}
        >
          ×
        </button>
      </div>
      {Object.entries(d)
        .filter(([, v]) => v !== undefined && v !== null && String(v).length > 0)
        .map(([k, v]) => (
          <div key={k} style={{ marginBottom: 12 }}>
            <div style={{ color: '#6b7280', fontSize: 10, textTransform: 'uppercase', marginBottom: 3, letterSpacing: '0.08em' }}>
              {k.replace(/_/g, ' ')}
            </div>
            <div style={{ color: '#d1d5db', wordBreak: 'break-word', fontFamily: typeof v === 'number' ? "'JetBrains Mono', monospace" : 'inherit' }}>
              {String(v)}
            </div>
          </div>
        ))}
    </div>
  )
}

// ── Layout helper ─────────────────────────────────────────────────────────────

interface GraphData {
  nodes: Array<{ id: string; type: string; data: Record<string, unknown> }>
  edges: Array<{ id: string; source: string; target: string; relationship?: string }>
}

function layoutNodes(raw: GraphData['nodes']): Node[] {
  const toolNodes = raw.filter(n => n.type === 'tool_execution')
  const findingNodes = raw.filter(n => n.type === 'finding')

  const positioned: Node[] = []

  toolNodes.forEach((n, i) => {
    positioned.push({
      id: n.id, type: n.type, data: n.data,
      position: { x: i * 230, y: 0 },
    })
  })

  findingNodes.forEach((n, i) => {
    positioned.push({
      id: n.id, type: n.type, data: n.data,
      position: { x: i * 210, y: 200 },
    })
  })

  return positioned
}

function buildEdges(rawEdges: GraphData['edges']): Edge[] {
  return rawEdges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    animated: false,
    label: e.relationship ?? 'triggered',
    labelStyle: { fill: '#4b5563', fontSize: 9, fontFamily: 'Inter, sans-serif' },
    labelBgStyle: { fill: BG.base, fillOpacity: 0.8 },
    style: { stroke: '#374151', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#374151', width: 12, height: 12 },
  }))
}

// ── Main component ────────────────────────────────────────────────────────────

interface ExecutionGraphProps {
  graphData: GraphData | null | undefined
  liveNodes?: Array<{ id: string; type: string; data: Record<string, unknown> }>
  liveEdges?: Array<{ id: string; source: string; target: string; relationship?: string }>
  isRunning?: boolean
}

export default function ExecutionGraph({ graphData, liveNodes = [], liveEdges = [], isRunning }: ExecutionGraphProps) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)

  const mergedNodes = graphData
    ? [...graphData.nodes, ...liveNodes.filter(ln => !graphData.nodes.find(n => n.id === ln.id))]
    : liveNodes

  const mergedEdges = graphData
    ? [...graphData.edges, ...liveEdges.filter(le => !graphData.edges.find(e => e.id === le.id))]
    : liveEdges

  const initialNodes: Node[] = layoutNodes(mergedNodes)
  const initialEdges: Edge[] = buildEdges(mergedEdges)

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  // Re-layout when data changes (live updates)
  useEffect(() => {
    setNodes(layoutNodes(mergedNodes))
    setEdges(buildEdges(mergedEdges))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mergedNodes.length, mergedEdges.length])

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(prev => prev?.id === node.id ? null : node)
  }, [])

  const hasData = mergedNodes.length > 0

  if (!hasData) {
    return (
      <div
        style={{
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          height: 380, color: '#4b5563', fontSize: 13,
          border: `1px solid ${BG.border}`, borderRadius: 10,
          gap: 12,
        }}
      >
        <GitFork size={28} style={{ opacity: 0.4 }} />
        <p>
          {isRunning
            ? 'Building execution graph…'
            : 'Execution graph available for active scans'}
        </p>
      </div>
    )
  }

  return (
    <div style={{ height: 480, border: `1px solid ${BG.border}`, borderRadius: 10, position: 'relative' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={NODE_TYPES}
        fitView
        style={{ background: BG.base, borderRadius: 10 }}
      >
        <Background color={BG.border} gap={24} />
        <Controls style={{ background: BG.surface, border: `1px solid ${BG.border}` }} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'tool_execution') return TOOL_BG
            const sev = String((n.data as Record<string, unknown>).severity ?? 'info').toLowerCase()
            return SEVERITY_COLOR[sev as keyof typeof SEVERITY_COLOR] ?? SEVERITY_COLOR.info
          }}
          style={{ background: BG.surface, border: `1px solid ${BG.border}` }}
        />
      </ReactFlow>
      {selectedNode && (
        <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  )
}
