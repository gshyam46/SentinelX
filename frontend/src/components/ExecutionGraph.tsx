import React, { useState, useCallback } from 'react'
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
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

// ── Node color helpers ────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#0284c7',
}

// ── Custom node: Tool ─────────────────────────────────────────────────────────

function ToolNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div
      style={{
        background: '#1a7fd4',
        color: '#fff',
        padding: '8px 14px',
        borderRadius: 8,
        fontSize: 12,
        fontWeight: 600,
        border: '2px solid #2563eb',
        minWidth: 120,
        textAlign: 'center',
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div style={{ fontSize: 10, opacity: 0.75, marginBottom: 2 }}>TOOL</div>
      <div>{String(data.tool_name ?? data.label ?? 'Tool')}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

// ── Custom node: Finding ──────────────────────────────────────────────────────

function FindingNode({ data }: { data: Record<string, unknown> }) {
  const sev = String(data.severity ?? 'info').toLowerCase()
  const color = SEV_COLORS[sev] ?? '#6b7280'
  const isKev = Boolean(data.known_exploited)

  return (
    <div
      style={{
        background: color + '22',
        color: '#f9fafb',
        padding: '8px 14px',
        borderRadius: 8,
        fontSize: 11,
        border: `2px solid ${color}`,
        minWidth: 140,
        maxWidth: 200,
        position: 'relative',
      }}
    >
      <Handle type="target" position={Position.Top} />
      {isKev && (
        <div
          style={{
            position: 'absolute',
            top: -8,
            right: -8,
            background: '#dc2626',
            color: '#fff',
            fontSize: 9,
            fontWeight: 700,
            padding: '1px 5px',
            borderRadius: 4,
          }}
        >
          KEV
        </div>
      )}
      <div
        style={{
          fontSize: 9,
          fontWeight: 700,
          color,
          textTransform: 'uppercase',
          marginBottom: 2,
        }}
      >
        {sev}
      </div>
      <div style={{ fontSize: 11, lineHeight: 1.3 }}>
        {String(data.title ?? data.label ?? 'Finding').slice(0, 60)}
      </div>
      <Handle type="source" position={Position.Bottom} />
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
  return (
    <div
      style={{
        position: 'absolute',
        right: 0,
        top: 0,
        bottom: 0,
        width: 280,
        background: '#111827',
        borderLeft: '1px solid #1f2937',
        padding: 16,
        overflowY: 'auto',
        zIndex: 10,
        fontSize: 12,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <span style={{ fontWeight: 700, color: '#f9fafb' }}>Node Detail</span>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: 16 }}
        >
          ×
        </button>
      </div>
      {Object.entries(d).map(([k, v]) => (
        <div key={k} style={{ marginBottom: 8 }}>
          <div style={{ color: '#6b7280', fontSize: 10, textTransform: 'uppercase', marginBottom: 2 }}>{k}</div>
          <div style={{ color: '#d1d5db', wordBreak: 'break-word' }}>{String(v ?? '—')}</div>
        </div>
      ))}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface GraphData {
  nodes: Array<{ id: string; type: string; data: Record<string, unknown> }>
  edges: Array<{ id: string; source: string; target: string; relationship?: string }>
}

interface ExecutionGraphProps {
  graphData: GraphData | null | undefined
}

function layoutNodes(
  raw: GraphData['nodes']
): Node[] {
  const toolNodes = raw.filter(n => n.type === 'tool_execution')
  const findingNodes = raw.filter(n => n.type === 'finding')

  const toolSpacing = 220
  const findingSpacing = 200

  const positioned: Node[] = []

  toolNodes.forEach((n, i) => {
    positioned.push({
      id: n.id,
      type: n.type,
      data: n.data,
      position: { x: i * toolSpacing, y: 0 },
    })
  })

  findingNodes.forEach((n, i) => {
    positioned.push({
      id: n.id,
      type: n.type,
      data: n.data,
      position: { x: i * findingSpacing, y: 180 },
    })
  })

  return positioned
}

export default function ExecutionGraph({ graphData }: ExecutionGraphProps) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)

  const initialNodes: Node[] = graphData ? layoutNodes(graphData.nodes) : []
  const initialEdges: Edge[] = graphData
    ? graphData.edges.map(e => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: false,
        style: { stroke: '#4b5563', strokeWidth: 1.5 },
      }))
    : []

  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node)
  }, [])

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: 300,
          color: '#4b5563',
          fontSize: 13,
          border: '1px solid #1f2937',
          borderRadius: 8,
        }}
      >
        No graph data available (passive scans do not generate an execution graph)
      </div>
    )
  }

  return (
    <div style={{ height: 480, border: '1px solid #1f2937', borderRadius: 8, position: 'relative' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={NODE_TYPES}
        fitView
        style={{ background: '#0a0d14' }}
      >
        <Background color="#1f2937" gap={20} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'tool_execution') return '#1a7fd4'
            const sev = String((n.data as Record<string, unknown>).severity ?? 'info').toLowerCase()
            return SEV_COLORS[sev] ?? '#6b7280'
          }}
          style={{ background: '#111827' }}
        />
      </ReactFlow>
      {selectedNode && (
        <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  )
}
