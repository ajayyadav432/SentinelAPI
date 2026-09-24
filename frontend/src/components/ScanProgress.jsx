import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function ScanProgress({ progress, logs, currentEndpoint, isScanning, onCancel }) {
  const terminalEndRef = useRef(null);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className={isScanning ? "radar-dot radar-dot-active" : "radar-dot"} />
          <span style={{ fontWeight: 600, fontSize: '15px' }}>
            {isScanning ? 'Zero-Trust Attack Engine Running...' : 'Audit Run Finished'}
          </span>
          {currentEndpoint && (
            <code style={{
              background: 'rgba(56, 189, 248, 0.1)',
              color: '#38bdf8',
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '12px'
            }}>
              {currentEndpoint}
            </code>
          )}
        </div>
        <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--cyan-accent)' }}>
          {progress}%
        </span>
      </div>

      {/* Progress Bar Container */}
      <div style={{
        width: '100%',
        height: '8px',
        background: 'rgba(255, 255, 255, 0.08)',
        borderRadius: '4px',
        overflow: 'hidden',
        marginBottom: '16px'
      }}>
        <div style={{
          width: `${progress}%`,
          height: '100%',
          background: 'linear-gradient(90deg, #0284c7 0%, #38bdf8 70%, #a855f7 100%)',
          borderRadius: '4px',
          boxShadow: '0 0 12px rgba(56, 189, 248, 0.6)',
          transition: 'width 0.3s ease'
        }} />
      </div>

      {/* Real-time Streaming Attack Console */}
      <div style={{
        background: '#04060a',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        borderRadius: '8px',
        padding: '12px 16px',
        height: '140px',
        overflowY: 'auto',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        lineHeight: 1.6
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-dim)', marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '4px' }}>
          <Terminal size={13} />
          <span>Real-time Attack Vector Execution Stream</span>
        </div>
        {logs.map((log, idx) => {
          const isVuln = log.includes('Vulnerability') || log.includes('Discovered') || log.includes('BREACH');
          return (
            <div key={idx} style={{ color: isVuln ? '#f87171' : '#94a3b8', display: 'flex', gap: '8px' }}>
              <span style={{ color: 'var(--text-dim)' }}>&gt;</span>
              <span>{log}</span>
            </div>
          );
        })}
        <div ref={terminalEndRef} />
      </div>
    </div>
  );
}
