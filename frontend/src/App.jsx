import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import RiskMetrics from './components/RiskMetrics';
import ScanProgress from './components/ScanProgress';
import FindingCard from './components/FindingCard';
import AgenticChainView from './components/AgenticChainView';
import AttackGraphView from './components/AttackGraphView';
import PrRemediationModal from './components/PrRemediationModal';
import PentestChatbot from './components/PentestChatbot';
import ScanConfigModal from './components/ScanConfigModal';
import KeyModal from './components/KeyModal';
import { Shield, Zap, Search, Filter, Sparkles, Layers, Bot, Terminal, GitPullRequest } from 'lucide-react';

export default function App() {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentEndpoint, setCurrentEndpoint] = useState('');
  const [logs, setLogs] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('findings'); // 'findings', 'graph', 'agent'

  // Modals & Chat state
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [apiKey, setApiKey] = useState(localStorage.getItem('sentinel_gemini_key') || '');
  const [defaultSpec, setDefaultSpec] = useState('');
  const [selectedPatch, setSelectedPatch] = useState(null);
  const [isPrModalOpen, setIsPrModalOpen] = useState(false);
  const [chatFindingContext, setChatFindingContext] = useState(null);

  // Fetch demo spec on mount
  useEffect(() => {
    fetch('/api/demo/spec')
      .then(res => res.json())
      .then(data => {
        if (data.spec) setDefaultSpec(data.spec);
      })
      .catch(console.error);
  }, []);

  const handleStartScan = async (config) => {
    setIsScanning(true);
    setProgress(5);
    setCurrentEndpoint('Initializing Zero-Trust Ingestion Engine...');
    setLogs(['[+] SentinelAPI initialized.', '[+] Ingesting API specification topology...']);
    setFindings([]);
    setSummary(null);

    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });

      if (!res.ok) {
        throw new Error('Failed to launch scan.');
      }

      const data = await res.json();
      const currentScanId = data.scan_id;
      setScanId(currentScanId);

      // Connect to real-time WebSocket
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/scan/${currentScanId}`;
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'progress') {
            setProgress(msg.percent || 0);
            if (msg.current_endpoint) setCurrentEndpoint(msg.current_endpoint);
            if (msg.message) {
              setLogs(prev => [...prev.slice(-40), msg.message]);
            }
          } else if (msg.type === 'finding_detected') {
            setFindings(prev => [msg.finding, ...prev]);
            setLogs(prev => [...prev.slice(-40), `[!] BREACH CONFIRMED: ${msg.finding.vuln_type} on ${msg.finding.endpoint}`]);
          } else if (msg.type === 'scan_complete') {
            setIsScanning(false);
            setProgress(100);
            setCurrentEndpoint('Audit Finished');
            setSummary(msg.summary);
            setFindings(msg.summary.findings || []);
            setLogs(prev => [...prev, `[✓] Zero-Trust Scan Completed. Identified ${msg.summary.findings_count} flaws.`]);
            ws.close();
          } else if (msg.type === 'scan_error') {
            setIsScanning(false);
            setLogs(prev => [...prev, `[-] Scan Error: ${msg.error}`]);
            ws.close();
          }
        } catch (e) {
          console.error('WS parse error:', e);
        }
      };

      ws.onerror = (err) => {
        console.error('WebSocket error:', err);
      };
    } catch (e) {
      console.error(e);
      setIsScanning(false);
      setLogs(prev => [...prev, `[-] Initialization Failed: ${e.message}`]);
    }
  };

  const handleGeneratePr = async (finding) => {
    try {
      const res = await fetch('/api/remediation/pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(finding)
      });
      if (res.ok) {
        const patch = await res.json();
        setSelectedPatch(patch);
        setIsPrModalOpen(true);
      }
    } catch (e) {
      console.error('Error generating PR patch:', e);
    }
  };

  const handleAskAi = (finding) => {
    setChatFindingContext(finding);
  };

  const filteredFindings = findings.filter(f => {
    const matchesFilter = activeFilter === 'ALL' || f.severity === activeFilter;
    const matchesSearch = !searchQuery || 
      f.vuln_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.owasp_tag.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        onOpenKeyModal={() => setIsKeyModalOpen(true)}
        apiKeySet={Boolean(apiKey)}
        isScanning={isScanning}
        onOpenNewScan={() => setIsConfigOpen(true)}
      />

      <main style={{ flex: 1, padding: '28px 36px', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
        {/* Welcome Hero Banner when idle */}
        {!summary && !isScanning && (
          <div className="glass-panel glow-cyan" style={{
            padding: '36px',
            marginBottom: '30px',
            background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.08) 0%, rgba(15, 23, 42, 0.95) 100%)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div style={{ maxWidth: '680px' }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', padding: '4px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: 600, marginBottom: '14px' }}>
                <Sparkles size={14} />
                <span>Next-Gen Zero-Trust API Vulnerability Scanner</span>
              </div>
              <h1 style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-0.8px', lineHeight: 1.2, marginBottom: '12px' }}>
                Find the API vulnerability before the breach headline does.
              </h1>
              <p style={{ color: 'var(--text-muted)', fontSize: '15px', lineHeight: 1.6, marginBottom: '20px' }}>
                SentinelAPI pairs deterministic authorization fuzzing with Google Gemini 2.0 Flash reasoning to uncover
                Broken Object Level Authorization (IDOR), Broken Function Level Authorization (BFLA), and excessive data exposure.
              </p>
              <div style={{ display: 'flex', gap: '14px' }}>
                <button
                  onClick={() => handleStartScan({
                    spec_content: defaultSpec,
                    target_base_url: 'http://127.0.0.1:8000/sandbox-target',
                    gemini_api_key: apiKey || undefined
                  })}
                  className="btn-primary"
                  style={{ padding: '12px 24px', fontSize: '15px' }}
                >
                  <Zap size={18} />
                  <span>Run Live Demo Audit (crAPI Target)</span>
                </button>
                <button
                  onClick={() => setIsConfigOpen(true)}
                  className="btn-secondary"
                  style={{ padding: '12px 20px', fontSize: '14px' }}
                >
                  <span>Custom Spec / URL</span>
                </button>
              </div>
            </div>

            <div style={{
              background: '#04060b',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '10px',
              padding: '20px',
              width: '340px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)'
            }}>
              <div style={{ color: 'var(--text-dim)', marginBottom: '10px', fontWeight: 600 }}>
                // TRACK C AUDIT SCOPE
              </div>
              <div style={{ color: '#f87171', marginBottom: '6px' }}>🔴 OWASP API1:2023 - BOLA / IDOR</div>
              <div style={{ color: '#fb923c', marginBottom: '6px' }}>🟠 OWASP API5:2023 - BFLA (Admin Escalation)</div>
              <div style={{ color: '#facc15', marginBottom: '6px' }}>🟡 OWASP API3:2023 - Differential Schema Drift</div>
              <div style={{ color: '#60a5fa', marginBottom: '6px' }}>🔵 OWASP API4:2023 - Rate Limiting Bypass</div>
              <div style={{ color: '#a855f7', marginTop: '10px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                🤖 Autonomous Pentest Agent (Chaining)
              </div>
            </div>
          </div>
        )}

        {/* Live Progress Bar and Logs */}
        {(isScanning || logs.length > 0) && (
          <ScanProgress
            progress={progress}
            logs={logs}
            currentEndpoint={currentEndpoint}
            isScanning={isScanning}
          />
        )}

        {/* Risk Metrics Dashboard */}
        {summary && (
          <RiskMetrics
            summary={summary}
            activeFilter={activeFilter}
            onSelectFilter={setActiveFilter}
            scanId={scanId}
          />
        )}

        {/* View Mode Navigation Tabs */}
        {summary && (
          <div style={{
            display: 'flex',
            gap: '12px',
            marginBottom: '20px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            paddingBottom: '8px'
          }}>
            <button
              onClick={() => setActiveTab('findings')}
              className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
              style={{ fontSize: '14px' }}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={16} /> Audit Findings ({findings.length})
              </span>
            </button>
            <button
              onClick={() => setActiveTab('graph')}
              className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
              style={{ fontSize: '14px' }}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={16} color="var(--cyan-accent)" /> Visual Attack Graph
              </span>
            </button>
            <button
              onClick={() => setActiveTab('agent')}
              className={`tab-btn ${activeTab === 'agent' ? 'active' : ''}`}
              style={{ fontSize: '14px' }}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                <Bot size={16} color="var(--ai-purple)" /> Autonomous Exploit Chain
              </span>
            </button>
          </div>
        )}

        {/* View 1: Visual Attack Graph */}
        {summary && activeTab === 'graph' && summary.ai_risk_overview?.attack_graph && (
          <AttackGraphView graphData={summary.ai_risk_overview.attack_graph} />
        )}

        {/* View 2: Autonomous Pentest Agent Exploit Chain */}
        {summary && activeTab === 'agent' && summary.ai_risk_overview?.agentic_chain && (
          <AgenticChainView agenticData={summary.ai_risk_overview.agentic_chain} />
        )}

        {/* View 3: Findings Section */}
        {summary && activeTab === 'findings' && findings.length > 0 && (
          <div>
            {/* Filter and Search Bar */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '18px',
              gap: '16px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 800 }}>
                  Identified Vulnerabilities
                </h2>
                <span className="badge" style={{ background: 'rgba(255,255,255,0.08)', color: 'var(--text-main)' }}>
                  {filteredFindings.length} of {findings.length}
                </span>
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                {/* Search Input */}
                <div style={{ position: 'relative', width: '260px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '12px', top: '11px', color: 'var(--text-dim)' }} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search vulnerabilities..."
                    style={{
                      width: '100%',
                      padding: '8px 12px 8px 34px',
                      background: '#090d16',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                      color: 'var(--text-main)',
                      fontSize: '12px'
                    }}
                  />
                </div>

                {/* Filter Pill */}
                <button
                  onClick={() => setActiveFilter('ALL')}
                  className="btn-secondary"
                  style={{
                    padding: '6px 12px',
                    fontSize: '12px',
                    color: activeFilter === 'ALL' ? 'var(--cyan-accent)' : undefined
                  }}
                >
                  <Filter size={13} />
                  <span>{activeFilter === 'ALL' ? 'All Severities' : `Filtered: ${activeFilter}`}</span>
                </button>
              </div>
            </div>

            {/* Findings Cards List */}
            {filteredFindings.map((finding) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                onGeneratePr={handleGeneratePr}
                onAskAi={handleAskAi}
              />
            ))}
          </div>
        )}
      </main>

      {/* Floating Pentest AI Chatbot */}
      <PentestChatbot
        scanId={scanId}
        findingContext={chatFindingContext}
        apiKey={apiKey}
      />

      {/* PR Remediation Modal */}
      <PrRemediationModal
        isOpen={isPrModalOpen}
        onClose={() => setIsPrModalOpen(false)}
        patchData={selectedPatch}
      />

      {/* Config and Key Modals */}
      <ScanConfigModal
        isOpen={isConfigOpen}
        onClose={() => setIsConfigOpen(false)}
        onStartScan={handleStartScan}
        defaultSpecText={defaultSpec}
      />

      <KeyModal
        isOpen={isKeyModalOpen}
        onClose={() => setIsKeyModalOpen(false)}
        onSaveKey={(k) => {
          setApiKey(k);
          localStorage.setItem('sentinel_gemini_key', k);
        }}
        currentKey={apiKey}
      />
    </div>
  );
}
