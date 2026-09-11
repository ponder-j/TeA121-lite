import { useEffect, useMemo, useRef } from 'react';
import { RotateCcw } from 'lucide-react';
import type { CfgEdge, CfgNode } from '../types/generated';

const NODE_WIDTH = 220;
const HORIZONTAL_GAP = 32;
const VERTICAL_GAP = 82;
const PADDING = 20;
const BACK_EDGE_GUTTER = 32;
const MAX_VISIBLE_ROWS = 7;
type PositionedNode = CfgNode & { index: number; rank: number; x: number; y: number; height: number };

function nodeRows(node: CfgNode) { return node.ir ?? []; }
function nodeHeight(node: CfgNode) {
  const visibleRows = Math.max(1, Math.min(MAX_VISIBLE_ROWS, nodeRows(node).length));
  return 84 + visibleRows * 18;
}
function blockLabel(node: CfgNode) {
  const label = node.label.trim();
  if (/^(?:bb|block)[._-]?\d+$/i.test(label) || /^%?\d+$/.test(label)) return '';
  return label.replace(/^bb[._-]/i, '');
}

/** A compact layered layout that keeps branches side by side and back edges visible. */
function layout(nodes: CfgNode[], edges: CfgEdge[]) {
  const order = new Map(nodes.map((node, index) => [node.id, index]));
  const outgoing = new Map<string, CfgEdge[]>();
  edges.forEach(edge => outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge]));
  const roots = nodes.filter(node => !edges.some(edge => edge.target === node.id));
  const rank = new Map<string, number>(); const visiting = new Set<string>(); const visited = new Set<string>();
  const walk = (id: string, depth: number) => {
    rank.set(id, Math.max(rank.get(id) ?? 0, depth));
    if (visiting.has(id) || visited.has(id)) return;
    visiting.add(id); for (const edge of outgoing.get(id) ?? []) if (!visiting.has(edge.target)) walk(edge.target, depth + 1);
    visiting.delete(id); visited.add(id);
  };
  roots.forEach(node => walk(node.id, 0)); nodes.forEach(node => { if (!rank.has(node.id)) walk(node.id, rank.size); });
  const layers = new Map<number, CfgNode[]>();
  nodes.forEach(node => { const key = rank.get(node.id) ?? 0; layers.set(key, [...(layers.get(key) ?? []), node]); });
  layers.forEach(layer => layer.sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0)));
  const contentWidth = Math.max(NODE_WIDTH, ...[...layers.values()].map(layer => layer.length * NODE_WIDTH + Math.max(0, layer.length - 1) * HORIZONTAL_GAP));
  const contentInset = PADDING + BACK_EDGE_GUTTER;
  const width = contentWidth + contentInset * 2;
  const yByRank = new Map<number, number>(); let y = PADDING;
  [...layers.keys()].sort((a, b) => a - b).forEach(key => { yByRank.set(key, y); y += Math.max(...(layers.get(key) ?? []).map(nodeHeight)) + VERTICAL_GAP; });
  const positioned: PositionedNode[] = [];
  layers.forEach((layer, key) => { const layerWidth = layer.length * NODE_WIDTH + Math.max(0, layer.length - 1) * HORIZONTAL_GAP; const startX = contentInset + (contentWidth - layerWidth) / 2; layer.forEach((node, index) => positioned.push({ ...node, index: node.displayIndex ?? (order.get(node.id) ?? index) + 1, rank: key, x: startX + index * (NODE_WIDTH + HORIZONTAL_GAP), y: yByRank.get(key) ?? PADDING, height: nodeHeight(node) })); });
  positioned.sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0));
  return { nodes: positioned, width, height: Math.max(230, y - VERTICAL_GAP + PADDING) };
}

function edgePath(from: PositionedNode, to: PositionedNode, width: number, lane: number) {
  const sourceX = from.x + NODE_WIDTH / 2; const targetX = to.x + NODE_WIDTH / 2; const sourceY = from.y + from.height; const targetY = to.y;
  if (to.rank <= from.rank) {
    const useLeftRail = sourceX <= width / 2;
    const railX = useLeftRail ? PADDING + lane * 12 : width - PADDING - lane * 12;
    const sourceSide = useLeftRail ? from.x : from.x + NODE_WIDTH;
    const targetSide = useLeftRail ? to.x : to.x + NODE_WIDTH;
    const backSourceY = from.y + from.height * (from.id === to.id ? 0.7 : 0.5);
    const backTargetY = to.y + to.height * (from.id === to.id ? 0.3 : 0.5);
    const radius = Math.min(12, Math.max(4, Math.abs(backSourceY - backTargetY) / 4));
    const innerRailX = railX + (useLeftRail ? radius : -radius);
    return `M ${sourceSide} ${backSourceY} H ${innerRailX} Q ${railX} ${backSourceY} ${railX} ${backSourceY - radius} V ${backTargetY + radius} Q ${railX} ${backTargetY} ${innerRailX} ${backTargetY} H ${targetSide}`;
  }
  return `M ${sourceX} ${sourceY} C ${sourceX} ${sourceY + 34}, ${targetX} ${targetY - 34}, ${targetX} ${targetY}`;
}
function edgeLabel(edge: CfgEdge) { return edge.polarity ?? ''; }

export function CfgGraph({ nodes, edges, selected, onSelect }: { nodes: CfgNode[]; edges: CfgEdge[]; selected: string; onSelect: (node: CfgNode) => void }) {
  const graph = useMemo(() => layout(nodes, edges), [nodes, edges]); const positions = new Map(graph.nodes.map(node => [node.id, node])); const markerId = 'cfg-arrow'; const canvasRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const firstBackEdge = edges.find(edge => {
      const from = positions.get(edge.source);
      const to = positions.get(edge.target);
      return from && to && to.rank <= from.rank;
    });
    const from = firstBackEdge ? positions.get(firstBackEdge.source) : undefined;
    if (from) {
      const sourceCenter = from.x + NODE_WIDTH / 2;
      canvas.scrollLeft = sourceCenter <= graph.width / 2 ? 0 : Math.max(0, canvas.scrollWidth - canvas.clientWidth);
    } else {
      canvas.scrollLeft = Math.max(0, (canvas.scrollWidth - canvas.clientWidth) / 2);
    }
  }, [graph.width]);
  return <div className="cfg-canvas" aria-label="控制流图" ref={canvasRef}><div className="cfg-stage" style={{ width: graph.width, height: graph.height }}><svg className="cfg-lines" viewBox={`0 0 ${graph.width} ${graph.height}`} aria-hidden="true"><defs><marker id={markerId} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" /></marker></defs>{edges.map((edge, index) => { const from = positions.get(edge.source); const to = positions.get(edge.target); if (!from || !to) return null; const label = edgeLabel(edge); const back = to.rank <= from.rank; const backEdgesBefore = edges.slice(0, index).filter(previous => previous.source === edge.source && (positions.get(previous.target)?.rank ?? 0) <= from.rank).length; const useLeftRail = from.x + NODE_WIDTH / 2 <= graph.width / 2; const railX = useLeftRail ? PADDING + backEdgesBefore * 12 : graph.width - PADDING - backEdgesBefore * 12; const labelX = back ? railX + (useLeftRail ? 8 : -8) : (from.x + to.x) / 2 + NODE_WIDTH / 2; const labelY = back ? (from.y + from.height * 0.5 + to.y + to.height * 0.5) / 2 : (from.y + from.height + to.y) / 2; return <g key={`${edge.source}-${edge.target}-${index}`} className={`cfg-edge-group ${edge.polarity ?? ''} ${back ? 'back-edge' : ''}`}><path className="cfg-edge" d={edgePath(from, to, graph.width, backEdgesBefore)} markerEnd={`url(#${markerId})`} />{label && <text x={labelX} y={labelY} textAnchor={back ? (useLeftRail ? 'start' : 'end') : 'middle'} className="cfg-edge-label">{label}</text>}</g>; })}</svg>{graph.nodes.map(node => { const rows = nodeRows(node); const title = blockLabel(node); const isLoop = edges.some(edge => edge.source === node.id && (positions.get(edge.target)?.rank ?? 0) <= node.rank); return <button key={node.id} className={`cfg-node ${selected === node.id ? 'selected' : ''} ${node.kind ?? ''} ${isLoop ? 'has-loop' : ''}`} style={{ left: node.x, top: node.y, height: node.height }} onClick={() => onSelect(node)} aria-label={`基本块 ${node.index}${title ? `: ${title}` : ''}`}><span className="cfg-node-heading"><b>{node.index}</b>{title && <strong>{title}</strong>}{node.sourceLines?.length ? <small>行 {node.sourceLines.join(', ')}</small> : null}</span><span className="cfg-node-ir" aria-label="中间代码"><span className="cfg-node-ir-lines">{rows.length ? rows.slice(0, MAX_VISIBLE_ROWS).map(row => <code key={row.id}>{row.text}</code>) : <code className="cfg-node-empty">{node.instructions ? `${node.instructions} 条中间指令` : '无中间指令'}</code>}</span></span><span className="cfg-node-footer">{node.sourceLines?.length ? `源代码 ${node.sourceLines[0]} 行` : `${typeof node.instructions === 'number' ? node.instructions : rows.length} 条指令`}{isLoop && <><RotateCcw size={10} />循环回边</>}</span></button>; })}</div>{nodes.length === 0 && <div className="cfg-empty"><span>该函数没有可显示的基本块</span></div> }</div>;
}
