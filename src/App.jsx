import { useState } from 'react';
import InputPanel from './components/InputPanel';
import LogViewer from './components/LogViewer';
import InsightsPanel from './components/InsightsPanel';
import ResultDisplay from './components/ResultDisplay';
import ThreatVisualizer from './components/ThreatVisualizer';
import { analyzeContent } from './services/api';

export default function App() {
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
      {/* Header */}
      <header className="header">
        <h1>AI Secure Data Intelligence Platform</h1>
        <p className="subtitle">
          AI Gateway · Scanner · Log Analyzer · Risk Engine
        </p>
        <span className="badge">SISA Security</span>
      </header>

      {/* Main Layout */}
      <div className="main-layout">
        {/* Left: Input Panel */}
        <InputPanel
          onAnalyze={handleAnalyze}
          isLoading={isLoading}
        />

        {/* Right: Results */}
        <div className="results-area">
          {error && (
            <div className="error-message fade-in">
              <span>[!]</span> {error}
            </div>
          )}

          {!result && !isLoading && !error && (
            <div className="results-placeholder glass-card">
              <p style={{ fontWeight: 600, fontSize: '1.2rem', color: '#FFF', marginBottom: '8px' }}>SYSTEM IDLE</p>
              <p>
                Awaiting datastream. The autonomous mesh will intercept threats, engage deception layers,
                and generate forensic insight from any provided payload.
              </p>
            </div>
          )}

          {isLoading && (
            <div className="results-placeholder glass-card fade-in" style={{ borderColor: 'var(--accent-primary)' }}>
              <div className="placeholder-icon">
                <span className="spinner" style={{ width: 32, height: 32 }} />
              </div>
              <p style={{ letterSpacing: '0.1em' }}>INITIALIZING SCAN...</p>
            </div>
          )}

          {result && (
            <>
              {/* Peak Visualizer */}
              <ThreatVisualizer data={result} />

              {/* Insights Panel */}
              <InsightsPanel data={result} />

              {/* Log Viewer */}
              <LogViewer
                content={inputContent}
                findings={result.findings}
              />

              {/* Findings & JSON */}
              <ResultDisplay data={result} />
            </>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '32px 0 16px',
        color: 'var(--text-muted)',
        fontSize: '0.75rem',
      }}>
        AI Secure Data Intelligence Platform · Built for SISA
      </footer>
    </div>
  );
}
