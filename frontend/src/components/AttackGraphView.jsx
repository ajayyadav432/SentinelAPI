import React, { useState } from 'react';
import { ShieldAlert, Zap, Radio, AlertTriangle, ArrowRight, Info, Layers } from 'lucide-react';

export default function AttackGraphView({ graphData }) {
  if (!graphData || !graphData.nodes) return null;

  const [selectedNode, setSelectedNode] = useState(null);

  const { nodes, edges, summary } = graphData;

  const getNodeColor = (node) => {
    if (node.type === 'actor') return '#a855f7';
    if (node.type === 'victim') return '#38bdf8';
    if (node.status === 'compromised' || node.status === 'critical') return '#ef4444';
    if (node.status === 'high') return '#f97316';
    if (node.status === 'medium') return '#eab308';
    return '#10b981';
  };

  return (
    <div className="glass-panel glow-cyan" style={{ padding: '24px', marginBottom: '28px' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={18} color="var(--cyan-accent)" />
            <h3 style={{ fontSize: '18px', fontWeight: 800 }}>Topological API Attack Graph</h3>
            <span className="badge badge-critical">Active Breach Path</span>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Interactive threat model mapping adversary reconnaissance, zero-trust token swaps, and exfiltrated asset targets.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '6px 14px', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '11px', color: '#f87171', fontWeight: 600 }}>COMPROMISED ASSETS</span>
            <div style={{ fontSize: '16px', fontWeight: 800, color: '#ef4444' }}>{summary?.compromised_assets || 3}</div>
          </div>
          <div style={{ background: 'rgba(168, 85, 247, 0.1)', border: '1px solid rgba(168, 85, 247, 0.3)', padding: '6px 14px', borderRadius: '6px', textAlign: 'center' }}>
            <span style={{ fontSize: '11px', color: '#d8b4fe', fontWeight: 600 }}>CRITICAL PATHS</span>
            <div style={{ fontSize: '16px', fontWeight: 800, color: '#a855f7' }}>{summary?.critical_paths || 3}</div>
          </div>
        </div>
      </div>

      {/* SVG Interactive Canvas */}
      <div style={{
        background: '#04070e',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '10px',
        position: 'relative',
        overflow: 'hidden',
        minHeight: '440px'
      }}>
        {/* Ambient Grid Background */}
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'radial-gradient(rgba(56, 189, 248, 0.1) 1px, transparent 1px)',
          backgroundSize: '24px 24px',
          opacity: 0.5,
          pointerEvents: 'none'
        }} />

        <svg width="100%" height="440" viewBox="0 0 920 440" style={{ display: 'block' }}>
          <defs>
            <linearGradient id="grad-crit" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#a855f7" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
            <linearGradient id="grad-exfil" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#f97316" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#ef4444" />
            </marker>
            <marker id="arrow-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#a855f7" />
            </marker>
          </defs>

          {/* Render Connecting Edges */}
          {edges.map((edge) => {
            const src = nodes.find(n => n.id === edge.source);
            const tgt = nodes.find(n => n.id === edge.target);
            if (!src || !tgt) return null;

            const isCrit = edge.severity === 'CRITICAL';
            const strokeColor = isCrit ? 'url(#grad-crit)' : '#38bdf8';

            // Quadratic bezier curve midpoint
            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2;
            const pathD = `M ${src.x + 40} ${src.y + 15} Q ${midX} ${midY - 10} ${tgt.x - 10} ${tgt.y + 15}`;

            return (
              <g key={edge.id}>
                <path
                  d={pathD}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={isCrit ? "2.5" : "1.5"}
                  strokeDasharray={edge.animated ? "5, 5" : "none"}
                  markerEnd={isCrit ? "url(#arrow)" : "url(#arrow-purple)"}
                  opacity={0.85}
                >
                  {edge.animated && (
                    <animate attributeName="stroke-dashoffset" from="30" to="0" dur="1.2s" repeatCount="indefinite" />
                  )}
                </path>
                {/* Edge Label Pill */}
                <rect
                  x={midX - 55}
                  y={midY - 22}
                  width="110"
                  height="18"
                  rx="4"
                  fill="#0c111d"
                  stroke={isCrit ? "rgba(239, 68, 68, 0.4)" : "rgba(56, 189, 248, 0.3)"}
                />
                <text
                  x={midX}
                  y={midY - 9}
                  fill={isCrit ? "#fca5a5" : "#7dd3fc"}
                  fontSize="8.5"
                  fontFamily="var(--font-mono)"
                  fontWeight="600"
                  textAnchor="middle"
                >
                  {edge.label.slice(0, 19)}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const color = getNodeColor(node);
            const isSelected = selectedNode?.id === node.id;
            const isActor = node.type === 'actor' || node.type === 'victim';
            const isAsset = node.type === 'asset';

            return (
              <g
                key={node.id}
                onClick={() => setSelectedNode(node)}
                style={{ cursor: 'pointer' }}
                transform={`translate(${node.x - 20}, ${node.y - 10})`}
              >
                {/* Glow ring on click or critical */}
                {(isSelected || node.status === 'compromised') && (
                  <rect
                    x="-6"
                    y="-6"
                    width="192"
                    height="52"
                    rx="10"
                    fill="none"
                    stroke={color}
                    strokeWidth="2"
                    opacity={0.6}
                  >
                    <animate attributeName="stroke-width" values="1;3;1" dur="2s" repeatCount="indefinite" />
                  </rect>
                )}

                {/* Node Box */}
                <rect
                  x="0"
                  y="0"
                  width="180"
                  height="40"
                  rx="8"
                  fill="#0b0f19"
                  stroke={color}
                  strokeWidth={isSelected ? "2" : "1.2"}
                />

                {/* Type Indicator Icon Dot */}
                <circle cx="16" cy="20" r="5" fill={color} />

                {/* Node Text Label */}
                <text
                  x="30"
                  y="18"
                  fill="#f1f5f9"
                  fontSize="10.5"
                  fontWeight="700"
                  fontFamily="var(--font-sans)"
                >
                  {node.label.length > 20 ? node.label.slice(0, 20) + '...' : node.label}
                </text>

                <text
                  x="30"
                  y="31"
                  fill={isAsset ? '#f87171' : isActor ? '#c084fc' : '#94a3b8'}
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                >
                  {node.type.toUpperCase()}: {node.status}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div style={{
            position: 'absolute',
            bottom: '16px',
            left: '16px',
            right: '16px',
            background: 'rgba(13, 19, 32, 0.95)',
            backdropFilter: 'blur(10px)',
            border: `1px solid ${getNodeColor(selectedNode)}`,
            borderRadius: '8px',
            padding: '12px 18px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontSize: '14px', color: '#f1f5f9' }}>{selectedNode.label}</strong>
                <span className="badge" style={{ background: 'rgba(255,255,255,0.08)', color: getNodeColor(selectedNode) }}>
                  {selectedNode.type}
                </span>
                {selectedNode.findings_count > 0 && (
                  <span className="badge badge-critical">{selectedNode.findings_count} Vulns</span>
                )}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {selectedNode.description}
              </div>
            </div>

            <button
              onClick={() => setSelectedNode(null)}
              className="btn-secondary"
              style={{ padding: '4px 10px', fontSize: '11px' }}
            >
              Dismiss
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
