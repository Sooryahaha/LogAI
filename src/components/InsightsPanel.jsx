/**
 * InsightsPanel — B&W cyberpunk redesign
 * Payload Analysis Engine moved to top, always visible in the panel.
 */
export default function InsightsPanel({ data }) {
  if (!data) return null;

  const {
    summary, insights, findings, ai_findings = [],
    risk_score, risk_level, action, forensic_report, attack_narrative,
  } = data;

  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings)    if (riskCounts[f.risk] !== undefined) riskCounts[f.risk]++;
  for (const f of ai_findings) if (riskCounts[f.risk] !== undefined) riskCounts[f.risk]++;

  const typeCounts = {};
  for (const f of findings) typeCounts[f.type] = (typeCounts[f.type] || 0) + 1;

  const totalFindings = findings.length + ai_findings.length;

  const actionIcon = { masked: '[M]', blocked: '[B]', allowed: '[A]' };
  const statusColor = { CRITICAL: '#FFFFFF', WARNING: '#AAAAAA', INFO: '#666666' };

  const MITRE_GROUPS = [
    { tactic: 'INITIAL ACCESS',      types: ['xss', 'sql_injection', 'log4shell'] },
    { tactic: 'EXECUTION',           types: ['command_injection', 'rce'] },
    { tactic: 'PERSISTENCE',         types: ['rfi', 'lfi'] },
    { tactic: 'PRIVILEGE ESCALATION',types: ['idor', 'privilege'] },
    { tactic: 'DEFENSE EVASION',     types: ['waf_bypass', 'obfuscation'] },
    { tactic: 'CREDENTIAL ACCESS',   types: ['password', 'brute_force', 'secret', 'hardcoded'] },
    { tactic: 'DISCOVERY',           types: ['network', 'scan'] },
    { tactic: 'LATERAL MOVEMENT',    types: ['ssrf'] },
  ];

  return (
    <div className="glass-card slide-up insights-panel">
      <div className="card-title">SECURITY INSIGHTS</div>

      {/* Attack Narrative */}
      {attack_narrative && (
        <div className="attack-narrative fade-in">
          {attack_narrative}
          <span className="typewriter-cursor" />
        </div>
      )}

      {/* Summary text */}
      <div className="summary-text">{summary}</div>

      {/* Stats Bar */}
      <div className="summary-bar" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className={`stat-value risk-${risk_level}`}>{risk_score}</div>
          <div className="stat-label">RISK SCORE</div>
        </div>
        <div className="stat-card">
          <div className={`stat-value risk-${risk_level}`} style={{ fontSize: '1.1rem', letterSpacing: '0.05em' }}>
            {risk_level?.toUpperCase()}
          </div>
          <div className="stat-label">RISK LEVEL</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{totalFindings}</div>
          <div className="stat-label">ANOMALIES</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ fontSize: '1rem' }}>
            <span className={`action-badge ${action}`}>
              {actionIcon[action] || '•'} {action?.toUpperCase()}
            </span>
          </div>
          <div className="stat-label">ACTION</div>
        </div>
      </div>

      {/* ── Payload Analysis Engine + MITRE side by side ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 24 }}>

        {/* Payload Analysis Engine */}
        {findings.length > 0 && (
          <div className="payload-engine-box">
            <div className="section-label">PAYLOAD ANALYSIS ENGINE</div>

            <div className="payload-sig">
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>
                MATCHED SIGNATURE
              </div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.08em' }}>
                {Object.keys(typeCounts)[0]?.toUpperCase() || 'UNKNOWN'}
              </div>
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
                EXTRACTED IoC
              </div>
              <div className="payload-ioc">
                {findings[0]?.match || findings[0]?.description || 'Data string extracted'}
              </div>
            </div>

            {findings.slice(0, 4).map((f, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '5px 10px', marginBottom: 4,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: 'var(--r-sm)',
              }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-muted)' }}>
                  L{f.line || '?'} ◆ {f.type?.toUpperCase()}
                </span>
                <span className={`risk-badge ${f.risk}`}>{f.risk}</span>
              </div>
            ))}
          </div>
        )}

        {/* MITRE ATT&CK Tactics */}
        {totalFindings > 0 && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '16px 20px' }}>
            <div className="section-label">MITRE ATT&CK® TACTICS</div>
            {MITRE_GROUPS.map(group => {
              const isActive =
                findings.some(f => group.types.some(t => f.type?.includes(t))) ||
                ai_findings.some(a => group.types.some(t => a.type?.toLowerCase().includes(t)));
              return (
                <div key={group.tactic} className={`mitre-row ${isActive ? 'active' : ''}`}>
                  <span className="mitre-row-label">{group.tactic}</span>
                  {isActive && <span className="mitre-detected-badge">DETECTED</span>}
                </div>
              );
            })}
          </div>
        )}

        {/* PCI-DSS Impact */}
        {(forensic_report?.pci_dss_violations?.length > 0) && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '16px 20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div className="section-label" style={{ marginBottom: 0 }}>PCI-DSS VIOLATIONS</div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', border: '1px solid var(--border-bright)', color: 'var(--text-primary)', padding: '1px 8px', borderRadius: 2 }}>
                {forensic_report.pci_dss_violations.length}
              </span>
            </div>
            {forensic_report.pci_dss_violations.map((v, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, padding: '8px 10px', borderLeft: '2px solid var(--text-primary)', background: 'var(--bg-card)', borderRadius: '0 3px 3px 0', marginBottom: 6 }}>
                <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', lineHeight: 1.4 }}>{v}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* AI Deep Scan Anomalies */}
      {ai_findings.length > 0 && (
        <div style={{ marginBottom: 20, padding: '14px 18px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)' }}>
          <div className="section-label">ADVANCED AI DETECTIONS</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {ai_findings.map((ai, idx) => (
              <div key={idx} style={{
                padding: '9px 14px', background: 'var(--bg-card)',
                borderLeft: `2px solid ${ai.risk === 'critical' ? '#FFF' : ai.risk === 'high' ? '#888' : '#444'}`,
                borderRadius: '0 3px 3px 0', display: 'flex', flexDirection: 'column', gap: 3,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-primary)' }}>{ai.type}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)' }}>L:{ai.line}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{ai.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actionable Insights */}
      <div className="section-label">ACTIONABLE INSIGHTS</div>
      <ul className="insight-list" style={{ marginBottom: 24 }}>
        {insights.map((insight, idx) => (
          <li key={idx} className="insight-item">{insight}</li>
        ))}
      </ul>

      {/* SISA Forensic Report */}
      {forensic_report && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.15em' }}>
              SISA FORENSIC REPORT
            </span>
            {forensic_report.status && (
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.6rem', fontWeight: 700,
                border: '1px solid var(--border-bright)', color: 'var(--text-primary)',
                padding: '2px 10px', borderRadius: 2, letterSpacing: '0.1em',
              }}>
                {forensic_report.status}
              </span>
            )}
          </div>

          {forensic_report.root_cause && (
            <div style={{ marginBottom: 14 }}>
              <div className="forensic-section-title">ROOT CAUSE</div>
              <div style={{ padding: '10px 14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {forensic_report.root_cause}
              </div>
            </div>
          )}

          {forensic_report.patterns?.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div className="forensic-section-title">MITRE ATT&CK MAPPING</div>
              {forensic_report.patterns.map((p, i) => (
                <div key={i} style={{ padding: '10px 14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', marginBottom: 6 }}>
                  <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.7rem', letterSpacing: '0.08em', marginBottom: 4 }}>{p.name}</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.68rem', fontFamily: 'var(--font-mono)', marginBottom: 6 }}>{p.evidence}</div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {[p.mitre_tactic, p.mitre_technique].map((tag, ti) => tag && (
                      <span key={ti} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)', border: '1px solid var(--border)', padding: '1px 7px', borderRadius: 2 }}>
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {forensic_report.remediation?.length > 0 && (
            <div>
              <div className="forensic-section-title">REMEDIATION STEPS</div>
              <ol style={{ margin: 0, paddingLeft: 18 }}>
                {forensic_report.remediation.map((step, i) => (
                  <li key={i} style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: 6, lineHeight: 1.5, fontFamily: 'var(--font-body)' }}>
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
