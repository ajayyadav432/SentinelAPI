import React, { useState } from 'react';
import { X, Key, Check, ShieldCheck } from 'lucide-react';

export default function KeyModal({ isOpen, onClose, onSaveKey, currentKey }) {
  if (!isOpen) return null;

  const [keyInput, setKeyInput] = useState(currentKey || '');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    onSaveKey(keyInput);
    setSaved(true);
    setTimeout(() => {
      setSaved(false);
      onClose();
    }, 800);
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 110,
      padding: '20px'
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '480px', padding: '24px', background: '#0e1422' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Key size={18} color="var(--ai-purple)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700 }}>Google Gemini 2.0 AI Brain</h3>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '14px', lineHeight: 1.5 }}>
          Enter your Gemini API Key to enable live LLM reasoning for authorization flow analysis, adaptive fuzzing, and code remediation.
        </p>

        <input
          type="password"
          value={keyInput}
          onChange={(e) => setKeyInput(e.target.value)}
          placeholder="AIzaSy..."
          style={{
            width: '100%',
            padding: '10px 14px',
            background: '#06080d',
            border: '1px solid rgba(255,255,255,0.12)',
            borderRadius: '8px',
            color: 'var(--text-main)',
            fontSize: '13px',
            fontFamily: 'var(--font-mono)',
            marginBottom: '16px'
          }}
        />

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button onClick={handleSave} className="btn-primary" style={{ background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)' }}>
            {saved ? <Check size={14} color="#fff" /> : <ShieldCheck size={14} />}
            <span>{saved ? 'Saved!' : 'Save Key'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
