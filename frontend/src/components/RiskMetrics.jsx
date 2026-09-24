import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ShieldCheck, Download, FileText } from 'lucide-react';

export default function RiskMetrics({ summary, activeFilter, onSelectFilter, scanId }) {
  if (!summary) return null;

  const data = [
    { name: 'Critical', value: summary.critical_count, color: '#ef4444' },
    { name: 'High', value: summary.high_count, color: '#f97316' },
    { name: 'Medium', value: summary.medium_count, color: '#eab308' },
    { name: 'Low', value: summary.low_count, color: '#3b82f6' }
  ].filter(d => d.value > 0);

  const getScoreColor = (score) => {
    if (score >= 75) return '#ef4444';
    if (score >= 45) return '#f97316';
    if (score >= 20) return '#eab308';
    return '#10b981';
  };

  const getRiskLabel = (score) => {
    if (score >= 75) return 'CRITICAL BREACH RISK';
    if (score >= 45) return 'HIGH EXPOSURE';
    if (score >= 20) return 'MODERATE POSTURE';
    return 'LOW RISK';
  };

  const scoreColor = getScoreColor(summary.overall_risk_score);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr auto', gap: '20px', marginBottom: '24px' }}>
      {/* Risk Score Card */}
      <div className="glass-panel" style={{ padding: '22px', position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
              Zero-Trust Risk Index
            </span>
            <div style={{ fontSize: '44px', fontWeight: 800, color: scoreColor, lineHeight: 1.1, marginTop: '8px' }}>
              {summary.overall_risk_score}
              <span style={{ fontSize: '20px', color: 'var(--text-dim)', fontWeight: 500 }}>/100</span>
            </div>
            <div style={{ display: 'inline-block', marginTop: '6px', fontSize: '11px', fontWeight: 700, color: scoreColor, letterSpacing: '0.5px' }}>
              {getRiskLabel(summary.overall_risk_score)}
            </div>
          </div>
          
          <div style={{ width: '90px', height: '90px' }}>
            {data.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data}
                    innerRadius={28}
                    outerRadius={40}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {data.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                <ShieldCheck size={36} color="#10b981" />
              </div>
            )}
          </div>
        </div>

        <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-muted)' }}>
          <span>Endpoints Tested: <strong style={{ color: 'var(--text-main)' }}>{summary.scanned_endpoints}</strong></span>
          <span>Duration: <strong style={{ color: 'var(--text-main)' }}>{summary.duration_seconds}s</strong></span>
        </div>
      </div>

      {/* Severity Filter Counters */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
        {/* Critical */}
        <div
          onClick={() => onSelectFilter(activeFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
          className={`glass-panel ${activeFilter === 'CRITICAL' ? 'glow-red' : ''}`}
          style={{
            padding: '18px',
            cursor: 'pointer',
            borderLeft: '4px solid #ef4444',
            background: activeFilter === 'CRITICAL' ? 'rgba(239, 68, 68, 0.12)' : undefined
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: '#f87171', fontWeight: 600 }}>CRITICAL</span>
            <AlertOctagon size={18} color="#ef4444" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 800, marginTop: '8px', color: '#ef4444' }}>
            {summary.critical_count}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Immediate breach risk</span>
        </div>

        {/* High */}
        <div
          onClick={() => onSelectFilter(activeFilter === 'HIGH' ? 'ALL' : 'HIGH')}
          className={`glass-panel`}
          style={{
            padding: '18px',
            cursor: 'pointer',
            borderLeft: '4px solid #f97316',
            background: activeFilter === 'HIGH' ? 'rgba(249, 115, 22, 0.12)' : undefined
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: '#fb923c', fontWeight: 600 }}>HIGH</span>
            <AlertTriangle size={18} color="#f97316" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 800, marginTop: '8px', color: '#f97316' }}>
            {summary.high_count}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Major access flaw</span>
        </div>

        {/* Medium */}
        <div
          onClick={() => onSelectFilter(activeFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
          className="glass-panel"
          style={{
            padding: '18px',
            cursor: 'pointer',
            borderLeft: '4px solid #eab308',
            background: activeFilter === 'MEDIUM' ? 'rgba(234, 179, 8, 0.12)' : undefined
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: '#facc15', fontWeight: 600 }}>MEDIUM</span>
            <AlertCircle size={18} color="#eab308" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 800, marginTop: '8px', color: '#eab308' }}>
            {summary.medium_count}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Data & rate limits</span>
        </div>

        {/* Low / Info */}
        <div
          onClick={() => onSelectFilter(activeFilter === 'LOW' ? 'ALL' : 'LOW')}
          className="glass-panel"
          style={{
            padding: '18px',
            cursor: 'pointer',
            borderLeft: '4px solid #3b82f6',
            background: activeFilter === 'LOW' ? 'rgba(59, 130, 246, 0.12)' : undefined
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: '#60a5fa', fontWeight: 600 }}>LOW / MISC</span>
            <Info size={18} color="#3b82f6" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: 800, marginTop: '8px', color: '#60a5fa' }}>
            {summary.low_count}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Headers & config</span>
        </div>
      </div>

      {/* Report Export Button Card */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '10px' }}>
        <a
          href={`/api/scan/${scanId}/report.html`}
          target="_blank"
          rel="noreferrer"
          className="btn-primary"
          style={{ textDecoration: 'none', justifyContent: 'center' }}
        >
          <FileText size={16} />
          <span>Audit Report</span>
        </a>
        <a
          href={`/api/scan/${scanId}/report.json`}
          target="_blank"
          rel="noreferrer"
          className="btn-secondary"
          style={{ textDecoration: 'none', justifyContent: 'center', fontSize: '12px' }}
        >
          <Download size={14} />
          <span>Export JSON</span>
        </a>
      </div>
    </div>
  );
}
