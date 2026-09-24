import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Copy, Check, ShieldAlert, Sparkles, Terminal, Wrench, GitPullRequest, Bot } from 'lucide-react';

export default function FindingCard({ finding, onGeneratePr, onAskAi }) {
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState('poc'); // 'poc', 'ai', 'fix'
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-safe';
    }
  };

  const handleCopyCurl = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(finding.reproduction_curl || '');
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleCopyCode = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(finding.code_fix_example || '');
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div
      className={`glass-panel ${finding.severity === 'CRITICAL' ? 'glow-red' : ''}`}
      style={{
        marginBottom: '16px',
        overflow: 'hidden',
        borderLeft: `5px solid ${
          finding.severity === 'CRITICAL' ? '#ef4444' :
          finding.severity === 'HIGH' ? '#f97316' :
          finding.severity === 'MEDIUM' ? '#eab308' : '#3b82f6'
        }`
      }}
    >
      {/* Header Row (Clickable) */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '18px 22px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          cursor: 'pointer',
          background: expanded ? 'rgba(255, 255, 255, 0.02)' : 'transparent'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1 }}>
          <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
            {finding.severity}
          </span>
          <span style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            background: 'rgba(255, 255, 255, 0.06)',
            padding: '3px 8px',
            borderRadius: '4px',
            color: 'var(--text-muted)'
          }}>
            {finding.owasp_tag}
          </span>
          <span style={{
            fontSize: '11px',
            fontWeight: 700,
            background: 'rgba(239, 68, 68, 0.15)',
            color: '#f87171',
            padding: '3px 8px',
            borderRadius: '4px'
          }}>
            CVSS {finding.cvss_score}
          </span>
          <div>
            <div style={{ fontWeight: 700, fontSize: '15px', color: '#f1f5f9' }}>
              {finding.vuln_type}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '2px', display: 'flex', gap: '8px' }}>
              <span style={{ color: 'var(--cyan-accent)', fontWeight: 600 }}>{finding.method}</span>
              <code style={{ color: 'var(--text-muted)' }}>{finding.endpoint}</code>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Generate Fix PR Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (onGeneratePr) onGeneratePr(finding);
            }}
            className="btn-primary"
            style={{ padding: '5px 12px', fontSize: '12px', background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)' }}
            title="Generate automated GitHub Pull Request patch"
          >
            <GitPullRequest size={13} />
            <span>Fix PR</span>
          </button>

          {/* Ask AI Copilot Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (onAskAi) onAskAi(finding);
            }}
            className="btn-secondary"
            style={{ padding: '5px 10px', fontSize: '12px', color: '#d8b4fe', borderColor: 'rgba(168, 85, 247, 0.3)' }}
            title="Ask AI Pentester about this flaw"
          >
            <Bot size={13} color="var(--ai-purple)" />
            <span>Ask AI</span>
          </button>

          <button
            onClick={handleCopyCurl}
            className="btn-secondary"
            style={{ padding: '5px 10px', fontSize: '11px' }}
            title="Copy reproducible cURL command"
          >
            {copiedCurl ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
            <span>{copiedCurl ? 'Copied' : 'cURL'}</span>
          </button>

          {expanded ? <ChevronUp size={18} color="var(--text-dim)" /> : <ChevronDown size={18} color="var(--text-dim)" />}
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div style={{ padding: '0 22px 22px 22px', borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
          {/* Sub-tabs */}
          <div style={{ display: 'flex', gap: '8px', margin: '14px 0 16px 0', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <button
              onClick={() => setActiveTab('poc')}
              className={`tab-btn ${activeTab === 'poc' ? 'active' : ''}`}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <Terminal size={14} /> Proof of Concept (PoC)
              </span>
            </button>
            <button
              onClick={() => setActiveTab('ai')}
              className={`tab-btn ${activeTab === 'ai' ? 'active' : ''}`}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <Sparkles size={14} color="var(--ai-purple)" /> AI Risk & Explanation
              </span>
            </button>
            <button
              onClick={() => setActiveTab('fix')}
              className={`tab-btn ${activeTab === 'fix' ? 'active' : ''}`}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <Wrench size={14} /> Remediation & Code Fix
              </span>
            </button>
          </div>

          {/* Tab 1: PoC */}
          {activeTab === 'poc' && (
            <div>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '10px' }}>
                <strong>Verified Exploit Evidence:</strong> {finding.evidence}
              </p>
              
              <div style={{ marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>
                    Reproducible Attack cURL Command
                  </span>
                  <button onClick={handleCopyCurl} className="btn-secondary" style={{ padding: '3px 8px', fontSize: '11px' }}>
                    {copiedCurl ? <Check size={11} color="#34d399" /> : <Copy size={11} />}
                    <span>{copiedCurl ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="code-block" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {finding.reproduction_curl}
                </pre>
              </div>

              {finding.response_snippet && (
                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
                    Observed Response Payload Snippet
                  </span>
                  <pre className="code-block" style={{ color: '#f87171' }}>
                    {finding.response_snippet}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: AI Risk & Explanation */}
          {activeTab === 'ai' && (
            <div style={{ background: 'rgba(168, 85, 247, 0.05)', border: '1px solid rgba(168, 85, 247, 0.2)', borderRadius: '8px', padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <Sparkles size={16} color="var(--ai-purple)" />
                <span style={{ fontWeight: 700, fontSize: '14px', color: '#e9d5ff' }}>
                  Gemini 2.0 Flash Security Analysis
                </span>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.6, marginBottom: '12px' }}>
                {finding.plain_english_summary}
              </p>
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', borderLeft: '3px solid #ef4444', padding: '10px 14px', borderRadius: '4px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#f87171' }}>Business Risk Impact: </span>
                <span style={{ fontSize: '12px', color: '#fca5a5' }}>{finding.business_impact}</span>
              </div>
            </div>
          )}

          {/* Tab 3: Remediation & Code Fix */}
          {activeTab === 'fix' && (
            <div>
              <div style={{ marginBottom: '14px' }}>
                <h4 style={{ fontSize: '13px', color: 'var(--cyan-accent)', marginBottom: '8px' }}>
                  Actionable Developer Remediation Checklist
                </h4>
                <ul style={{ paddingLeft: '20px', fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.7 }}>
                  {finding.remediation_steps.map((step, sIdx) => (
                    <li key={sIdx}>{step}</li>
                  ))}
                </ul>
              </div>

              {finding.code_fix_example && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>
                      Recommended Defense-in-Depth Code Fix
                    </span>
                    <button onClick={handleCopyCode} className="btn-secondary" style={{ padding: '3px 8px', fontSize: '11px' }}>
                      {copiedCode ? <Check size={11} color="#34d399" /> : <Copy size={11} />}
                      <span>{copiedCode ? 'Copied' : 'Copy Fix'}</span>
                    </button>
                  </div>
                  <pre className="code-block" style={{ color: '#34d399', whiteSpace: 'pre-wrap' }}>
                    {finding.code_fix_example}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
