import React, { useState } from 'react';
import { X, GitPullRequest, Copy, Check, Download, GitBranch, ShieldCheck } from 'lucide-react';

export default function PrRemediationModal({ isOpen, onClose, patchData }) {
  if (!isOpen || !patchData) return null;

  const [copied, setCopied] = useState(false);
  const [applied, setApplied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(patchData.git_patch);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([patchData.git_patch], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-fix-${patchData.target_file.split('/').pop().replace('.py', '')}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.8)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 110,
      padding: '20px'
    }}>
      <div className="glass-panel glow-cyan" style={{
        width: '100%',
        maxWidth: '720px',
        maxHeight: '90vh',
        overflowY: 'auto',
        padding: '26px',
        background: '#090d16'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <GitPullRequest size={20} color="var(--cyan-accent)" />
            <h3 style={{ fontSize: '17px', fontWeight: 800 }}>Automated Fix Pull Request</h3>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        {/* PR Metadata */}
        <div style={{ background: '#05070d', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '14px', marginBottom: '16px' }}>
          <div style={{ fontWeight: 700, fontSize: '14px', color: '#f1f5f9', marginBottom: '6px' }}>
            {patchData.pr_title}
          </div>
          <div style={{ display: 'flex', gap: '14px', fontSize: '12px', color: 'var(--text-muted)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <GitBranch size={13} color="var(--ai-purple)" />
              <code>{patchData.branch_name}</code>
            </span>
            <span>File: <code>{patchData.target_file}</code></span>
          </div>
        </div>

        {/* Unified Diff View */}
        <div style={{ marginBottom: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>
              Git Unified Diff Patch (git apply compatible)
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button onClick={handleCopy} className="btn-secondary" style={{ padding: '3px 8px', fontSize: '11px' }}>
                {copied ? <Check size={12} color="#34d399" /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy Diff'}</span>
              </button>
              <button onClick={handleDownload} className="btn-secondary" style={{ padding: '3px 8px', fontSize: '11px' }}>
                <Download size={12} />
                <span>.patch</span>
              </button>
            </div>
          </div>

          <pre style={{
            background: '#030509',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '8px',
            padding: '12px 14px',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            overflowX: 'auto',
            lineHeight: 1.6
          }}>
            {patchData.git_patch.split('\n').map((line, idx) => {
              const isAdd = line.startsWith('+') && !line.startsWith('+++');
              const isDel = line.startsWith('-') && !line.startsWith('---');
              return (
                <div key={idx} style={{
                  color: isAdd ? '#34d399' : isDel ? '#f87171' : line.startsWith('@@') ? '#38bdf8' : '#94a3b8',
                  background: isAdd ? 'rgba(52, 211, 153, 0.08)' : isDel ? 'rgba(239, 68, 68, 0.08)' : 'transparent'
                }}>
                  {line}
                </div>
              );
            })}
          </pre>
        </div>

        {/* PR Body / Advisory */}
        <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px', padding: '12px 16px', fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>Pull Request Advisory Summary</div>
          <p>{patchData.pr_body}</p>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
          <button onClick={onClose} className="btn-secondary">
            Close
          </button>
          <button
            onClick={() => {
              setApplied(true);
              setTimeout(() => setApplied(false), 2500);
            }}
            className="btn-primary"
            style={{ background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)' }}
          >
            <ShieldCheck size={15} />
            <span>{applied ? '✓ Branch Simulated!' : 'Simulate Pull Request'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
