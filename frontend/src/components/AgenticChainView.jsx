import React, { useState } from 'react';
import { Bot, CheckCircle, ArrowRight, ShieldAlert, Terminal, Copy, Check } from 'lucide-react';

export default function AgenticChainView({ agenticData }) {
  if (!agenticData) return null;

  const [copiedStep, setCopiedStep] = useState(null);

  const handleCopy = (curl, stepNum) => {
    navigator.clipboard.writeText(curl);
    setCopiedStep(stepNum);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  return (
    <div className="glass-panel glow-purple" style={{
      padding: '24px',
      marginBottom: '24px',
      background: 'linear-gradient(180deg, rgba(168, 85, 247, 0.08) 0%, rgba(15, 23, 42, 0.8) 100%)',
      border: '1px solid rgba(168, 85, 247, 0.3)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 14px rgba(168, 85, 247, 0.5)'
          }}>
            <Bot size={20} color="#fff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ fontSize: '17px', fontWeight: 800, color: '#f5f3ff' }}>
                {agenticData.chain_title}
              </h3>
              <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.25)', color: '#f87171', border: '1px solid #ef4444' }}>
                {agenticData.status}
              </span>
              <span className="badge" style={{ background: 'rgba(168, 85, 247, 0.2)', color: '#d8b4fe' }}>
                CVSS {agenticData.cvss_score}
              </span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
              <strong>Objective:</strong> {agenticData.target_objective}
            </p>
          </div>
        </div>
      </div>

      {/* Steps Visual Chain */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '16px' }}>
        {agenticData.steps.map((st) => (
          <div
            key={st.step_number}
            style={{
              background: 'rgba(10, 14, 23, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '8px',
              padding: '16px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: 'var(--ai-purple)',
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '12px',
                  fontWeight: 700
                }}>
                  {st.step_number}
                </span>
                <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-main)' }}>
                  {st.title}
                </span>
                <code style={{ fontSize: '11px', background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', padding: '2px 8px', borderRadius: '4px' }}>
                  {st.target_endpoint}
                </code>
              </div>

              <button
                onClick={() => handleCopy(st.curl_command, st.step_number)}
                className="btn-secondary"
                style={{ padding: '3px 8px', fontSize: '11px' }}
              >
                {copiedStep === st.step_number ? <Check size={11} color="#34d399" /> : <Copy size={11} />}
                <span>{copiedStep === st.step_number ? 'Copied' : 'cURL'}</span>
              </button>
            </div>

            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '6px' }}>
              <strong>Action:</strong> {st.action}
            </p>
            <p style={{ fontSize: '13px', color: '#60a5fa' }}>
              <strong>Observation:</strong> {st.observation}
            </p>
          </div>
        ))}
      </div>

      <div style={{ marginTop: '16px', background: 'rgba(239, 68, 68, 0.1)', borderLeft: '4px solid #ef4444', padding: '12px 16px', borderRadius: '4px' }}>
        <div style={{ fontSize: '13px', color: '#f87171', fontWeight: 600, marginBottom: '4px' }}>
          Autonomous Attack Impact
        </div>
        <div style={{ fontSize: '12px', color: '#fca5a5', lineHeight: 1.5 }}>
          {agenticData.impact_summary}
        </div>
      </div>
    </div>
  );
}
