/**
 * InsightsPanel — displays AI-generated summary, security insights,
 * risk breakdown, action taken, and SISA forensic report.
 */
export default function InsightsPanel({ data }) {
  if (!data) return null;

  const { summary, insights, findings, ai_findings = [], risk_score, risk_level, action, forensic_report, attack_narrative, security_graph, mcp_audit } = data;

  // Count findings by risk level (merging regex findings + AI findings)
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (riskCounts[f.risk] !== undefined) riskCounts[f.risk]++;
  }
  for (const f of ai_findings) {
    if (riskCounts[f.risk] !== undefined) riskCounts[f.risk]++;
  }

  // Count findings by type
  const typeCounts = {};
  for (const f of findings) {
    typeCounts[f.type] = (typeCounts[f.type] || 0) + 1;
  }

  const totalFindings = findings.length + ai_findings.length;
  const maxRisk = Math.max(...Object.values(riskCounts), 1); // For chart scaling
  const maxType = Math.max(...Object.values(typeCounts), 1); // For chart scaling

  // No string emojis per requirement
  const actionIcon = { masked: '[M]', blocked: '[B]', allowed: '[A]' };
  const statusIcon = { CRITICAL: '!', WARNING: '!', INFO: 'i' };
  const statusColor = { CRITICAL: 'var(--risk-critical)', WARNING: 'var(--risk-high)', INFO: 'var(--success)' };
  const riskColorMap = { critical: 'var(--risk-critical)', high: 'var(--risk-high)', medium: 'var(--risk-medium)', low: 'var(--risk-low)'};

  return (
    <div className="glass-card slide-up insights-panel">
      <div className="card-title">
        SECURITY INSIGHTS
      </div>

      {/* Attack Narrative Engine */}
      {attack_narrative && (
        <div className="attack-narrative fade-in">
          {attack_narrative}
          <span className="typewriter-cursor"></span>
        </div>
      )}

      {/* Summary */}
      <div className="summary-text">{summary}</div>

      {/* Stats Bar */}
      <div className="summary-bar" style={{ marginBottom: 16 }}>
        <div className="stat-card">
          <div className={`stat-value risk-${risk_level}`}>{risk_score}</div>
          <div className="stat-label">Risk Score</div>
        </div>
        <div className="stat-card">
          <div className={`stat-value risk-${risk_level}`}>
            {risk_level.toUpperCase()}
          </div>
          <div className="stat-label">Risk Level</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--accent-primary)' }}>
            {totalFindings}
          </div>
          <div className="stat-label">Total Anomalies</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            <span className={`action-badge ${action}`}>
              {actionIcon[action] || '•'} {action}
            </span>
          </div>
          <div className="stat-label">Action</div>
        </div>
      </div>

      {/* Enterprise SOC Insights — Payload Analysis and MITRE Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px', marginBottom: 24 }}>
        
        {/* Payload De-obfuscation / Detection Engine */}
        {findings.length > 0 && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-md)', padding: '20px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Payload Analysis Engine
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
              <div style={{ padding: '12px', background: '#FFFFFF', border: '1px solid #E5E7EB', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', marginBottom: '4px' }}>Matched Signature</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#111827', fontFamily: 'var(--font-mono)' }}>
                  {Object.keys(typeCounts)[0]?.toUpperCase() || 'UNKNOWN PAYLOAD'}
                </div>
              </div>

              <div style={{ padding: '12px', background: '#FFFFFF', border: '1px solid #E5E7EB', borderRadius: '6px', flex: 1 }}>
                <div style={{ fontSize: '0.65rem', fontWeight: 700, color: '#6B7280', textTransform: 'uppercase', marginBottom: '4px' }}>Extracted Indicator of Compromise (IoC)</div>
                <div style={{ fontSize: '0.75rem', color: '#DC2626', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', background: '#FEF2F2', padding: '8px', borderRadius: '4px', border: '1px solid #FCA5A5' }}>
                  {findings[0]?.match || findings[0]?.description || 'Data string extracted'}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Enterprise Matrix Heatmap */}
        {totalFindings > 0 && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-md)', padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                MITRE ATT&CK® TACTICS HIGHLIGHT
              </div>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {/* Render a grid of tactics. If finding relates to tactic, color it Red, else Gray */}
              {[
                { tactic: 'Initial Access', types: ['xss', 'sql_injection', 'log4shell'] },
                { tactic: 'Execution', types: ['command_injection', 'rce'] },
                { tactic: 'Persistence', types: ['rfi', 'lfi'] },
                { tactic: 'Privilege Escalation', types: ['idor', 'privilege'] },
                { tactic: 'Defense Evasion', types: ['waf_bypass', 'obfuscation'] },
                { tactic: 'Credential Access', types: ['password', 'brute_force', 'secret', 'hardcoded'] },
                { tactic: 'Discovery', types: ['network', 'scan'] },
                { tactic: 'Lateral Movement', types: ['ssrf'] },
              ].map(group => {
                // Check if any finding matches this tactic group
                const isActive = findings.some(f => group.types.some(t => f.type.includes(t))) || 
                                 ai_findings.some(a => group.types.some(t => a.type.toLowerCase().includes(t)));
                
                return (
                  <div key={group.tactic} style={{ 
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', 
                    padding: '8px 12px', 
                    background: isActive ? '#FEF2F2' : '#FFFFFF', 
                    border: `1px solid ${isActive ? '#FCA5A5' : '#E5E7EB'}`, 
                    borderRadius: '4px' 
                  }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: isActive ? 700 : 500, color: isActive ? '#B91C1C' : '#4B5563' }}>
                      {group.tactic}
                    </span>
                    {isActive && (
                      <span style={{ fontSize: '0.65rem', background: '#DC2626', color: '#FFF', padding: '2px 6px', borderRadius: '4px', fontWeight: 700 }}>
                        DETECTED
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* PCI-DSS Impact Map */}
        {(forensic_report?.pci_dss_violations && forensic_report.pci_dss_violations.length > 0) && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-md)', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                PCI-DSS Compliance Blast Radius
              </div>
              <div style={{ fontSize: '0.65rem', background: 'var(--text-primary)', color: 'var(--bg-primary)', padding: '2px 6px', fontWeight: 900, borderRadius: '4px' }}>
                {forensic_report.pci_dss_violations.length} VIOLATIONS
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {forensic_report.pci_dss_violations.map((violation, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '10px', borderLeft: '3px solid var(--risk-critical)', background: 'var(--bg-primary)', borderRadius: '0 4px 4px 0', border: '1px solid var(--border-glass)' }}>
                  <div style={{ color: 'var(--risk-critical)', fontSize: '1rem', lineHeight: 1 }}>⚠</div>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                    {violation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI Deep Scan Anomalies Layer */}
      {ai_findings && ai_findings.length > 0 && (
        <div style={{ marginBottom: 24, padding: '16px', background: 'var(--bg-card)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-md)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: 12 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Advanced AI Detections
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {ai_findings.map((ai, idx) => (
              <div key={idx} style={{ padding: '10px 14px', background: 'var(--bg-primary)', borderLeft: `3px solid ${riskColorMap[ai.risk]}`, borderRadius: '4px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{ai.type}</span>
                  <span style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>L: {ai.line}</span>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{ai.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Insights List */}
      <div style={{
        fontSize: '0.78rem', fontWeight: 600,
        color: 'var(--text-muted)', marginBottom: 8,
        textTransform: 'uppercase', letterSpacing: '0.05em',
      }}>
        Actionable Insights
      </div>
      <ul className="insight-list">
        {insights.map((insight, idx) => (
          <li key={idx} className="insight-item">
            {insight}
          </li>
        ))}
      </ul>

      {/* ── SISA Forensic Report ── */}
      {forensic_report && (
        <div className="forensic-report" style={{
          marginTop: 20,
          borderTop: '1px solid var(--border-glass)',
          paddingTop: 16,
        }}>
          {/* Header */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            marginBottom: 12,
          }}>
            <span style={{
              fontSize: '0.85rem', fontWeight: 700,
              color: 'var(--text-primary)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
            }}>
              SISA Forensic Report
            </span>
            {forensic_report.status && (
              <span style={{
                marginLeft: 'auto',
                padding: '2px 12px',
                borderRadius: '12px',
                fontSize: '0.7rem',
                fontWeight: 700,
                letterSpacing: '0.05em',
                color: '#fff',
                background: statusColor[forensic_report.status] || '#666',
              }}>
                {statusIcon[forensic_report.status] || '•'} {forensic_report.status}
              </span>
            )}
          </div>

          {/* Root Cause */}
          {forensic_report.root_cause && (
            <div style={{ marginBottom: 14 }}>
              <div style={{
                fontSize: '0.72rem', fontWeight: 600,
                color: 'var(--text-muted)', marginBottom: 4,
                textTransform: 'uppercase', letterSpacing: '0.05em',
              }}>
                Root Cause
              </div>
              <div style={{
                padding: '8px 12px',
                background: 'rgba(255,68,68,0.08)',
                border: '1px solid rgba(255,68,68,0.2)',
                borderRadius: '8px',
                fontSize: '0.82rem',
                color: 'var(--text-secondary)',
                fontFamily: 'var(--font-mono)',
                lineHeight: 1.5,
              }}>
                {forensic_report.root_cause}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK Patterns */}
          {forensic_report.patterns && forensic_report.patterns.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{
                fontSize: '0.72rem', fontWeight: 600,
                color: 'var(--text-muted)', marginBottom: 8,
                textTransform: 'uppercase', letterSpacing: '0.05em',
              }}>
                [ MITRE ATT&CK MAPPING ]
              </div>
              <div style={{
                display: 'flex', flexDirection: 'column', gap: 6,
              }}>
                {forensic_report.patterns.map((p, i) => (
                  <div key={i} style={{
                    padding: '8px 12px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-glass)',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                  }}>
                    <div style={{
                      fontWeight: 600, color: 'var(--text-primary)',
                      marginBottom: 4,
                    }}>
                      {p.name}
                    </div>
                    <div style={{
                      color: 'var(--text-muted)', fontSize: '0.72rem',
                      marginBottom: 3,
                    }}>
                      {p.evidence}
                    </div>
                    <div style={{
                      display: 'flex', gap: 8, flexWrap: 'wrap',
                    }}>
                      <span style={{
                        padding: '2px 8px',
                        background: 'var(--bg-primary)',
                        border: '1px solid var(--border-glass)',
                        borderRadius: '10px',
                        fontSize: '0.68rem',
                        color: 'var(--text-secondary)',
                        fontFamily: 'var(--font-mono)',
                      }}>
                        {p.mitre_tactic}
                      </span>
                      <span style={{
                        padding: '2px 8px',
                        background: 'var(--bg-primary)',
                        border: '1px solid var(--border-glass)',
                        borderRadius: '10px',
                        fontSize: '0.68rem',
                        color: 'var(--text-secondary)',
                        fontFamily: 'var(--font-mono)',
                      }}>
                        {p.mitre_technique}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {forensic_report.remediation && forensic_report.remediation.length > 0 && (
            <div>
              <div style={{
                fontSize: '0.72rem', fontWeight: 600,
                color: 'var(--text-muted)', marginBottom: 8,
                textTransform: 'uppercase', letterSpacing: '0.05em',
              }}>
                [ REMEDIATION STEPS ]
              </div>
              <ol style={{
                margin: 0, paddingLeft: 20,
                listStyleType: 'decimal',
              }}>
                {forensic_report.remediation.map((step, i) => (
                  <li key={i} style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                    marginBottom: 6,
                    lineHeight: 1.5,
                  }}>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
