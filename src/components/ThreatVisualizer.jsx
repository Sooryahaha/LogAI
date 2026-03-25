import { useState, useEffect } from 'react';

export default function ThreatVisualizer({ data }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const [animatedAnomalies, setAnimatedAnomalies] = useState(0);

  const { risk_score, findings = [], ai_findings = [], risk_level } = data;
  const totalAnomalies = findings.length + ai_findings.length;
  const criticalCount = [...findings, ...ai_findings].filter(f => f.risk === 'critical').length;

  useEffect(() => {
    const duration = 1200;
    const steps = 50;
    const interval = duration / steps;
    let step = 0;
    const timer = setInterval(() => {
      step++;
      const ease = 1 - Math.pow(1 - step / steps, 4);
      setAnimatedScore(Math.round(risk_score * ease));
      setAnimatedAnomalies(Math.round(totalAnomalies * ease));
      if (step >= steps) {
        clearInterval(timer);
        setAnimatedScore(risk_score);
        setAnimatedAnomalies(totalAnomalies);
      }
    }, interval);
    return () => clearInterval(timer);
  }, [risk_score, totalAnomalies]);

  // SVG ring — all white, just thickness conveys severity
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animatedScore / 100) * circumference;

  // Ring glow intensity based on score
  let ringColor = '#444444';
  let ringGlow = 'none';
  if (animatedScore >= 40) { ringColor = '#888888'; }
  if (animatedScore >= 70) { ringColor = '#CCCCCC'; }
  if (animatedScore >= 90) { ringColor = '#FFFFFF'; ringGlow = '0 0 16px rgba(255,255,255,0.6)'; }

  return (
    <div className="glass-card slide-up visualizer-card">
      <div className="card-title" style={{ marginBottom: 18 }}>THREAT VECTOR ANALYSIS</div>

      <div style={{ display: 'flex', gap: '28px', alignItems: 'center', flexWrap: 'wrap' }}>

        {/* Radial Gauge */}
        <div className="risk-gauge-wrapper">
          <svg width="130" height="130" viewBox="0 0 130 130" style={{ transform: 'rotate(-90deg)' }}>
            {/* Track */}
            <circle cx="65" cy="65" r={radius} fill="none" stroke="#1A1A1A" strokeWidth="6" />
            {/* Progress */}
            <circle
              cx="65" cy="65" r={radius}
              fill="none"
              stroke={ringColor}
              strokeWidth="6"
              strokeLinecap="round"
              style={{
                strokeDasharray: circumference,
                strokeDashoffset: isNaN(offset) ? circumference : offset,
                transition: 'stroke-dashoffset 0.05s linear, stroke 0.4s ease',
                filter: ringGlow !== 'none' ? `drop-shadow(${ringGlow})` : 'none',
              }}
            />
          </svg>
          <div className="risk-gauge-center">
            <span className="risk-score-num">{animatedScore}</span>
            <span className="risk-score-label">RISK IDX</span>
          </div>
        </div>

        {/* KPI Grid */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))', gap: '10px' }}>

          <div className="kpi-card">
            <div className="kpi-label">VECTORED THREATS</div>
            <div className="kpi-value">{animatedAnomalies}</div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">CRITICAL SEV.</div>
            <div className={`kpi-value ${criticalCount > 0 ? 'critical' : ''}`}>
              {criticalCount}
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-label">AI INFERENCES</div>
            <div className="kpi-value">{ai_findings.length}</div>
          </div>

          <div className="kpi-card" style={{ gridColumn: 'span 1' }}>
            <div className="kpi-label">RISK LEVEL</div>
            <div
              className="kpi-value"
              style={{
                fontSize: '1rem', letterSpacing: '0.08em',
                color: risk_level === 'critical' ? '#FFF' : 'var(--text-primary)'
              }}
            >
              {risk_level?.toUpperCase() || '—'}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
