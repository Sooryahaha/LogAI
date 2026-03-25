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

      {/* SISA Automated Forensic Chain of Custody & Compliance Impact Map */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginBottom: 24 }}>
        
        {/* Forensic Attack Trajectory (SVG) */}
        {totalFindings > 0 && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-md)', padding: '16px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Forensic Attack Trajectory
            </div>
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '120px' }}>
              <svg width="100%" height="100" viewBox="0 0 400 100" style={{ maxWidth: '100%', overflow: 'visible' }}>
                <defs>
                  <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#FFF" />
                  </marker>
                  <marker id="blocked_arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#444" />
                  </marker>
                </defs>
                {/* Nodes */}
                <rect x="10" y="30" width="80" height="40" rx="4" fill="#0A0A0A" stroke="#555" strokeWidth="1" />
                <text x="50" y="54" fill="#FFF" fontSize="10" fontFamily="var(--font-mono)" textAnchor="middle">Threat Source</text>
                
                <rect x="160" y="30" width="80" height="40" rx="4" fill="#000" stroke="#FFF" strokeWidth="2" />
                <text x="200" y="54" fill="#FFF" fontSize="10" fontFamily="var(--font-cyber)" fontWeight="bold" textAnchor="middle">SISA MESH</text>

                <rect x="310" y="30" width="80" height="40" rx="4" fill="#0A0A0A" stroke="#333" strokeWidth="1" />
                <text x="350" y="54" fill="#666" fontSize="10" fontFamily="var(--font-mono)" textAnchor="middle">Internal Asset</text>

                {/* Edges */}
                <line x1="90" y1="50" x2="150" y2="50" stroke="#FFF" strokeWidth="2" strokeDasharray="4 4" markerEnd="url(#arrow)" />
                <line x1="240" y1="50" x2="300" y2="50" stroke="#333" strokeWidth="2" markerEnd="url(#blocked_arrow)" />

                {/* Labels */}
                <text x="125" y="42" fill="#CCC" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">
                  {Object.keys(typeCounts)[0] || 'payload'}
                </text>

                {action === 'blocked' && (
                  <text x="272" y="42" fill="#FFF" fontSize="9" fontWeight="bold" fontFamily="var(--font-mono)" textAnchor="middle">
                    [BLOCKED]
                  </text>
                )}
                {action !== 'blocked' && (
                  <text x="272" y="42" fill="#666" fontSize="8" fontFamily="var(--font-mono)" textAnchor="middle">
                    [PASSED]
                  </text>
                )}
              </svg>
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
              <div style={{ fontSize: '0.65rem', background: '#FFF', color: '#000', padding: '2px 6px', fontWeight: 900, borderRadius: '2px' }}>
                {forensic_report.pci_dss_violations.length} VIOLATIONS
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {forensic_report.pci_dss_violations.map((violation, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '8px', borderLeft: '2px solid #FFF', background: '#000' }}>
                  <div style={{ color: '#FFF', fontSize: '1rem', lineHeight: 1 }}>⚠</div>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#DDD', lineHeight: 1.4 }}>
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
