import React, { useState, useEffect } from 'react';
import { X, Play, Sparkles, FileCode, Server, Shield, Key } from 'lucide-react';

export default function ScanConfigModal({ isOpen, onClose, onStartScan, defaultSpecText }) {
  if (!isOpen) return null;

  const [specText, setSpecText] = useState(defaultSpecText || '');
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000/sandbox-target');
  const [userAToken, setUserAToken] = useState('');
  const [userBToken, setUserBToken] = useState('');
  const [geminiKey, setGeminiKey] = useState(localStorage.getItem('sentinel_gemini_key') || '');
  const [loadingDemo, setLoadingDemo] = useState(false);

  useEffect(() => {
    if (!specText && defaultSpecText) {
      setSpecText(defaultSpecText);
    }
  }, [defaultSpecText]);

  const handleLoadDemo = async () => {
    setLoadingDemo(true);
    try {
      const res = await fetch('/api/demo/spec');
      if (res.ok) {
        const data = await res.json();
        setSpecText(data.spec);
        setTargetUrl('http://127.0.0.1:8000/sandbox-target');
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDemo(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setSpecText(event.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handleLaunch = () => {
    if (geminiKey) {
      localStorage.setItem('sentinel_gemini_key', geminiKey);
    }
    onStartScan({
      spec_content: specText,
      target_base_url: targetUrl,
      user_a_token: userAToken || undefined,
      user_b_token: userBToken || undefined,
      gemini_api_key: geminiKey || undefined
    });
    onClose();
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '20px'
    }}>
      <div className="glass-panel glow-cyan" style={{
        width: '100%',
        maxWidth: '720px',
        maxHeight: '90vh',
        overflowY: 'auto',
        padding: '28px',
        background: '#0d131f'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield size={22} color="var(--cyan-accent)" />
            <h2 style={{ fontSize: '18px', fontWeight: 800 }}>Configure Zero-Trust API Audit</h2>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Demo Fast Preset */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.1) 0%, rgba(168, 85, 247, 0.1) 100%)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          borderRadius: '8px',
          padding: '14px 18px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px'
        }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '14px', color: '#e0f2fe' }}>
              One-Click Judge Demo Preset (Automotive crAPI)
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Loads the vulnerable microservice target with seeded BOLA, BFLA, and data leaks.
            </div>
          </div>
          <button
            type="button"
            onClick={handleLoadDemo}
            className="btn-primary"
            style={{ padding: '6px 14px', fontSize: '12px' }}
            disabled={loadingDemo}
          >
            <Sparkles size={14} />
            <span>{loadingDemo ? 'Loading...' : 'Load Preset'}</span>
          </button>
        </div>

        {/* Form Fields */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Target Base URL */}
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
              Target API Base URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. http://127.0.0.1:8000/sandbox-target or https://api.sandbox.com"
              style={{
                width: '100%',
                padding: '10px 14px',
                background: '#06080d',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: '13px'
              }}
            />
          </div>

          {/* OpenAPI Spec Content / File */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>
                OpenAPI / Swagger Spec (YAML or JSON)
              </label>
              <label style={{ fontSize: '12px', color: 'var(--cyan-accent)', cursor: 'pointer', fontWeight: 500 }}>
                Upload File
                <input type="file" accept=".yaml,.yml,.json" onChange={handleFileUpload} style={{ display: 'none' }} />
              </label>
            </div>
            <textarea
              rows={8}
              value={specText}
              onChange={(e) => setSpecText(e.target.value)}
              placeholder="Paste OpenAPI YAML or JSON specification here..."
              style={{
                width: '100%',
                padding: '12px 14px',
                background: '#06080d',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                color: '#38bdf8',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                resize: 'vertical'
              }}
            />
          </div>

          {/* Dual Identity Tokens for BOLA Testing */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Victim Token (User A) [Optional]
              </label>
              <input
                type="text"
                value={userAToken}
                onChange={(e) => setUserAToken(e.target.value)}
                placeholder="Defaults to auto-generated JWT"
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: '#06080d',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  color: 'var(--text-main)',
                  fontSize: '12px'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Attacker Token (User B) [Optional]
              </label>
              <input
                type="text"
                value={userBToken}
                onChange={(e) => setUserBToken(e.target.value)}
                placeholder="Defaults to auto-generated JWT"
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: '#06080d',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  color: 'var(--text-main)',
                  fontSize: '12px'
                }}
              />
            </div>
          </div>

          {/* Gemini API Key */}
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
              Google Gemini 2.0 Flash API Key [Optional]
            </label>
            <input
              type="password"
              value={geminiKey}
              onChange={(e) => setGeminiKey(e.target.value)}
              placeholder="AI Studio API Key (Leave empty to use built-in cyber intelligence engine)"
              style={{
                width: '100%',
                padding: '9px 12px',
                background: '#06080d',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                color: 'var(--text-main)',
                fontSize: '12px'
              }}
            />
          </div>
        </div>

        {/* Modal Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '24px', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '16px' }}>
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button onClick={handleLaunch} className="btn-primary">
            <Play size={15} />
            <span>Launch Zero-Trust Scan</span>
          </button>
        </div>
      </div>
    </div>
  );
}
