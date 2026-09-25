import React from 'react';
import { AlertTriangle, TrendingDown, ShieldCheck, Activity } from 'lucide-react';

export default function ClientFindingCard({ finding }) {
  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-safe';
    }
  };

  const getFriendlyTitle = (title) => {
    if (title.includes('BOLA') || title.includes('IDOR')) return 'Unauthorized Data Access';
    if (title.includes('BFLA')) return 'Unauthorized Action Privileges';
    if (title.includes('Schema Drift')) return 'Unexpected System Behavior';
    if (title.includes('Rate Limiting')) return 'Lack of Abuse Protection';
    return title;
  };

  return (
    <div
      className={`glass-panel`}
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
      <div style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className={`badge ${getSeverityBadgeClass(finding.severity)}`} style={{ fontSize: '13px', padding: '4px 10px' }}>
              {finding.severity} RISK
            </span>
            <h3 style={{ fontSize: '18px', fontWeight: 700, margin: 0, color: '#f1f5f9' }}>
              {getFriendlyTitle(finding.vuln_type)}
            </h3>
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Activity size={14} /> Affected Area: {finding.endpoint.split('/').slice(0,3).join('/')}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* What happened? */}
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', color: '#e2e8f0' }}>
              <AlertTriangle size={18} color="#fbbf24" />
              <strong style={{ fontSize: '14px' }}>What does this mean?</strong>
            </div>
            <p style={{ fontSize: '14px', color: 'var(--text-main)', lineHeight: 1.6, margin: 0 }}>
              {finding.plain_english_summary || "An issue was found that allows unintended behavior on the platform."}
            </p>
          </div>

          {/* Business Impact */}
          <div style={{ background: 'rgba(239, 68, 68, 0.05)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', color: '#fca5a5' }}>
              <TrendingDown size={18} color="#ef4444" />
              <strong style={{ fontSize: '14px', color: '#f87171' }}>Business Impact</strong>
            </div>
            <p style={{ fontSize: '14px', color: '#fca5a5', lineHeight: 1.6, margin: 0 }}>
              {finding.business_impact || "This could negatively affect users or business operations if left unresolved."}
            </p>
          </div>
        </div>

        <div style={{ marginTop: '20px', borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <ShieldCheck size={18} color="#34d399" />
            <strong style={{ fontSize: '14px', color: '#e2e8f0' }}>Recommended High-Level Solution</strong>
          </div>
          <ul style={{ margin: 0, paddingLeft: '24px', color: 'var(--text-dim)', fontSize: '14px', lineHeight: 1.6 }}>
            {finding.remediation_steps.slice(0, 2).map((step, idx) => (
              <li key={idx}>{step}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
