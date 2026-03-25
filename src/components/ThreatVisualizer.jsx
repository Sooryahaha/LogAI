import { useState, useEffect } from 'react';

/**
 * Peak D3-style Visualization Component
 * Renders animated radial gauges, KPI counters, MITRE ATT&CK heat strip,
 * and an active findings feed.
 */
export default function ThreatVisualizer({ data }) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const [animatedAnomalies, setAnimatedAnomalies] = useState(0);

  const { risk_score, findings = [], ai_findings = [], risk_level } = data;
  const totalAnomalies = findings.length + ai_findings.length;
  const criticalCount = [...findings, ...ai_findings].filter(f => f.risk === 'critical').length;

  useEffect(() => {
    // Animate numbers from 0 to target
    const duration = 1500;
    const steps = 60;
    const interval = duration / steps;
    let currentStep = 0;

    const timer = setInterval(() => {
      currentStep++;
      const progress = currentStep / steps;
      // Easing function: easeOutQuart
      const easeOut = 1 - Math.pow(1 - progress, 4);
      
      setAnimatedScore(Math.round(risk_score * easeOut));
      setAnimatedAnomalies(Math.round(totalAnomalies * easeOut));

      if (currentStep >= steps) {
        clearInterval(timer);
        setAnimatedScore(risk_score);
        setAnimatedAnomalies(totalAnomalies);
      }
    }, interval);

    return () => clearInterval(timer);
  }, [risk_score, totalAnomalies]);

  // Determine exact ring color for score
  let ringColor = 'var(--success)';
  if (animatedScore >= 40) ringColor = 'var(--warning)';
  if (animatedScore >= 70) ringColor = 'var(--risk-high)';
  if (animatedScore >= 90) ringColor = 'var(--risk-critical)';

  // Calculate SVG stroke offset for gauge (0 to 100)
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="glass-card slide-up visualizer-card" style={{ marginBottom: 32, padding: '24px 32px' }}>
      <div style={{ display: 'flex', gap: '32px', alignItems: 'center', flexWrap: 'wrap' }}>
        
        {/* Radial Gauge */}
        <div style={{ position: 'relative', width: '140px', height: '140px', flexShrink: 0 }}>
          <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
            {/* Background track */}
            <circle cx="70" cy="70" r={radius} fill="none" stroke="#222" strokeWidth="8" />
            {/* Animated progress ring */}
            <circle 
              cx="70" cy="70" r={radius} 
              fill="none" 
              stroke={ringColor} 
              strokeWidth="8"
              strokeLinecap="round"
              style={{
                strokeDasharray: circumference,
                strokeDashoffset: isNaN(strokeDashoffset) ? circumference : strokeDashoffset,
                transition: 'stroke-dashoffset 0.1s linear, stroke 0.3s'
              }}
            />
          </svg>
          {/* Centered text in gauge */}
          <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontFamily: 'var(--font-cyber)', fontSize: '2.5rem', fontWeight: 900, color: '#FFF', lineHeight: 1 }}>
              {animatedScore}
            </span>
            <span style={{ fontSize: '0.6rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 4 }}>
              RISK INDEX
            </span>
          </div>
        </div>

        {/* KPI Counters */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))', gap: '16px' }}>
          
          <div style={{ background: '#111', padding: '16px', borderRadius: '4px', border: '1px solid #333' }}>
            <div style={{ fontSize: '0.6rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Vectored Threats</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', color: '#FFF', fontWeight: 800 }}>{animatedAnomalies}</div>
          </div>
          
          <div style={{ background: '#111', padding: '16px', borderRadius: '4px', border: '1px solid #333' }}>
            <div style={{ fontSize: '0.6rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Critical Severity</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', color: criticalCount > 0 ? 'var(--risk-critical)' : '#FFF', fontWeight: 800 }}>{criticalCount}</div>
          </div>

          <div style={{ background: '#111', padding: '16px', borderRadius: '4px', border: '1px solid #333' }}>
            <div style={{ fontSize: '0.6rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>AI Inferences</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', color: ai_findings.length > 0 ? 'var(--risk-high)' : '#FFF', fontWeight: 800 }}>{ai_findings.length}</div>
          </div>

        </div>
      </div>

      {/* Tactic Strip */}
      <div style={{ marginTop: 32, paddingTop: 20, borderTop: '1px solid #222' }}>
        <div style={{ fontSize: '0.65rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>
          Identified MITRE Tactics
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {/* Mock MITRE strip — derives from findings broadly */}
          {['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement'].map(tactic => {
            // Very hacky heuristic to simulate MITRE lighting up
            const isActive = findings.some(f => 
              (tactic === 'Initial Access' && f.type.includes('sql') || f.type.includes('xss') || f.type.includes('rce')) ||
              (tactic === 'Credential Access' && f.type.includes('brute') || f.type.includes('password') || f.type.includes('key')) ||
              (tactic === 'Discovery' && f.type.includes('scan') || f.type.includes('error')) ||
              (tactic === 'Defense Evasion' && f.type.includes('waf')) ||
              (tactic === 'Lateral Movement' && f.risk === 'critical')
            ) || ai_findings.some(a => a.description.toLowerCase().includes(tactic.toLowerCase()));
            
            return (
              <div 
                key={tactic}
                style={{ 
                  padding: '4px 12px', 
                  fontSize: '0.65rem', 
                  fontFamily: 'var(--font-mono)',
                  color: isActive ? '#000' : '#555',
                  background: isActive ? '#FFF' : '#111',
                  border: `1px solid ${isActive ? '#FFF' : '#333'}`,
                  borderRadius: '2px',
                  boxShadow: isActive ? '0 0 8px rgba(255,255,255,0.2)' : 'none',
                  transition: 'all 0.3s'
                }}
              >
                {tactic}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
