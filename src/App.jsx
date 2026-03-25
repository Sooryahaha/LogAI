import { useState } from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import InputPanel from './components/InputPanel';
import LogViewer from './components/LogViewer';
import InsightsPanel from './components/InsightsPanel';
import ResultDisplay from './components/ResultDisplay';
import ThreatVisualizer from './components/ThreatVisualizer';
import IntelDashboard from './pages/IntelDashboard';
import { analyzeContent } from './services/api';

function MainScanner() {
  const [result, setResult] = useState(null);
  const [inputContent, setInputContent] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async (payload) => {
    setIsLoading(true);
    setError('');
    setResult(null);
    setInputContent(payload.content);
    try {
      const data = await analyzeContent(payload);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <h1>AI SECURE DATA INTELLIGENCE</h1>
          <p className="subtitle">AI GATEWAY ◆ SCANNER ◆ LOG ANALYZER ◆ RISK ENGINE</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div className="header-status">
            <div className={`status-dot ${!isLoading ? 'live' : ''}`} />
            {isLoading ? 'SCANNING...' : 'SYSTEM SECURE'}
          </div>
          <span className="badge">SISA CORE</span>
        </div>
      </header>

      {/* ── Main 2-col layout ── */}
      <div className="main-layout">
        {/* Left: Input Panel */}
        <InputPanel onAnalyze={handleAnalyze} isLoading={isLoading} />

        {/* Right: Results */}
        <div className="results-area">

          {error && (
            <div className="error-message fade-in">
              <span>[!]</span> {error}
            </div>
          )}

          {/* ── Link to Intel Dashboard ── */}
          <div className="glass-card fade-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px 32px', background: 'linear-gradient(90deg, var(--bg-card) 0%, rgba(20,20,20,1) 100%)', borderLeft: '4px solid var(--text-primary)' }}>
            <div>
              <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.2rem', color: 'var(--text-primary)', margin: '0 0 8px 0', letterSpacing: '0.1em' }}>SISA INTELLIGENCE DASHBOARD</h3>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-muted)', margin: 0 }}>Deploy Deception Honeypots & Run Adversarial Digital Twin Simulations.</p>
            </div>
            <Link to="/intel" style={{ padding: '16px 24px', background: 'var(--text-primary)', color: 'var(--bg-base)', border: 'none', borderRadius: 'var(--r-md)', fontFamily: 'var(--font-display)', fontSize: '0.9rem', fontWeight: 800, textDecoration: 'none', letterSpacing: '0.1em', transition: 'all 0.2s' }}>
              LAUNCH AI AUTH (Click Here) ⇗
            </Link>
          </div>

          {/* ── Empty state ── */}
          {!result && !isLoading && !error && (
            <div className="results-placeholder">
              <span style={{ fontSize: '1.5rem', marginBottom: 16, color: 'var(--text-dim)' }}>⬡</span>
              <p style={{ fontFamily: 'var(--font-display)', fontSize: '1rem', letterSpacing: '0.2em', color: 'var(--text-muted)', marginBottom: 12 }}>
                SYSTEM IDLE
              </p>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                Awaiting datastream — paste or upload a payload to begin forensic scan
              </p>
            </div>
          )}

          {/* ── Loading ── */}
          {isLoading && (
            <div className="results-placeholder fade-in" style={{ borderColor: 'var(--border-bright)' }}>
              <span className="spinner" style={{ width: 36, height: 36, marginBottom: 20 }} />
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', letterSpacing: '0.15em', color: 'var(--text-muted)' }}>
                INITIALIZING FORENSIC SCAN...
              </p>
            </div>
          )}

          {/* ── Results ── */}
          {result && (
            <>
              <ThreatVisualizer data={result} />
              <InsightsPanel data={result} />
              <ResultDisplay data={result} />
              <LogViewer content={inputContent} findings={result.findings} />
            </>
          )}
        </div>
      </div>

      {/* ── Footer ── */}
      <footer style={{
        textAlign: 'center', padding: '32px 0 16px',
        borderTop: '1px solid var(--border)', marginTop: 40,
        fontFamily: 'var(--font-mono)', fontSize: '0.75rem',
        color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase',
      }}>
        AI SECURE DATA INTELLIGENCE PLATFORM ◆ SISA SECURITY ◆ {new Date().getFullYear()}
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<MainScanner />} />
      <Route path="/intel" element={<IntelDashboard />} />
    </Routes>
  );
}
