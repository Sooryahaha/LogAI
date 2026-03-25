import { useState, useEffect } from 'react';

/**
 * AiSummary — Dedicated AI Analyst Narrative Panel
 * Features:
 * 1. Typewriter effect for the attack narrative.
 * 2. Forensic Verdict section based on the report status.
 * 3. Clinical, authoritative B&W aesthetic.
 */
export default function AiSummary({ data }) {
  const { summary, attack_narrative, forensic_report, risk_level } = data;
  const [displayedNarrative, setDisplayedNarrative] = useState('');
  const [isTyping, setIsTyping] = useState(false);

  useEffect(() => {
    if (attack_narrative) {
      setIsTyping(true);
      setDisplayedNarrative('');
      let i = 0;
      const interval = setInterval(() => {
        setDisplayedNarrative(attack_narrative.slice(0, i));
        i++;
        if (i > attack_narrative.length) {
          clearInterval(interval);
          setIsTyping(false);
        }
      }, 20); // Fast typing
      return () => clearInterval(interval);
    }
  }, [attack_narrative]);

  if (!summary && !attack_narrative) return null;

  return (
    <div className="glass-card slide-up ai-summary-panel">
      <div className="card-title">AI ANALYST VERDICT</div>

      <div className="ai-status-header">
        <div className="ai-avatar">
          <div className="ai-avatar-inner" />
          <div className="ai-avatar-pulse" />
        </div>
        <div className="ai-meta">
          <div className="ai-name">SISA-01 CORE</div>
          <div className="ai-task">FORENSIC RECONSTRUCTION</div>
        </div>
        <div className={`ai-risk-tag ${risk_level}`}>
          {risk_level?.toUpperCase()} RISK
        </div>
      </div>

      <div className="forensic-narrative-container">
        <div className="narrative-label">ATTACKER NARRATIVE (AI RECONSTRUCTION)</div>
        <div className="narrative-content">
          {displayedNarrative}
          {isTyping && <span className="terminal-cursor">_</span>}
        </div>
      </div>

      {forensic_report && (
        <div className="forensic-summary-box">
          <div className="summary-row">
            <span className="label">STATUS:</span>
            <span className={`value status-${forensic_report.status?.toLowerCase()}`}>
              {forensic_report.status || 'ANALYSIS COMPLETE'}
            </span>
          </div>
          <div className="summary-row">
            <span className="label">ROOT CAUSE:</span>
            <span className="value">{forensic_report.root_cause || 'Determining...'}</span>
          </div>
        </div>
      )}

      <div className="ai-summary-footer">
        <span className="summary-tag">VALIDATED BY SISA INTELLIGENCE MESH</span>
      </div>
    </div>
  );
}
