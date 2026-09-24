import React from 'react';
import { ShieldAlert, Zap, Key, ExternalLink, Activity } from 'lucide-react';

export default function Navbar({ onOpenKeyModal, apiKeySet, isScanning, onOpenNewScan }) {
  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 28px',
      borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
      background: 'rgba(7, 9, 14, 0.85)',
      backdropFilter: 'blur(12px)',
      position: 'sticky',
      top: 0,
      zIndex: 50
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '38px',
          height: '38px',
          borderRadius: '10px',
          background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(56, 189, 248, 0.45)'
        }}>
          <ShieldAlert size={22} color="#07090e" strokeWidth={2.5} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '18px', fontWeight: 800, letterSpacing: '-0.5px' }}>SentinelAPI</span>
            <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
              Zero-Trust AI
            </span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', letterSpacing: '0.2px' }}>
            AmiHacks 2026 · Track C: Deep-Tech
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          background: 'rgba(15, 23, 42, 0.6)',
          borderRadius: '20px',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          fontSize: '12px'
        }}>
          <span className={isScanning ? "radar-dot radar-dot-active" : "radar-dot"} />
          <span style={{ color: isScanning ? '#f87171' : '#34d399', fontWeight: 500 }}>
            {isScanning ? 'Attack Fuzzing Active' : 'Scanner Ready'}
          </span>
        </div>

        <button
          onClick={onOpenKeyModal}
          className="btn-secondary"
          style={{ padding: '7px 12px', fontSize: '12px' }}
          title="Configure Gemini 2.0 Flash API Key"
        >
          <Key size={14} color={apiKeySet ? "#34d399" : "#facc15"} />
          <span>{apiKeySet ? "AI Brain Active" : "Set Gemini Key"}</span>
        </button>

        <button
          onClick={onOpenNewScan}
          className="btn-primary"
          style={{ padding: '7px 16px', fontSize: '13px' }}
        >
          <Zap size={15} />
          <span>New Scan</span>
        </button>
      </div>
    </header>
  );
}
