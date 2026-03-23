/**
 * InsightsPanel — displays AI-generated summary, security insights,
 * risk breakdown, and action taken.
 */
export default function InsightsPanel({ data }) {
  if (!data) return null;

  const { summary, insights, findings, risk_score, risk_level, action } = data;

  // Count findings by risk level
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (riskCounts[f.risk] !== undefined) riskCounts[f.risk]++;
  }

  // Count findings by type
  const typeCounts = {};
  for (const f of findings) {
    typeCounts[f.type] = (typeCounts[f.type] || 0) + 1;
  }

  const actionIcon = { masked: '🔒', blocked: '🛑', allowed: '✅' };

  return (
    <div className="glass-card slide-up insights-panel">
      <div className="card-title">
        <span className="icon">🧠</span>
        Security Insights
      </div>

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
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>
            {findings.length}
          </div>
          <div className="stat-label">Findings</div>
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

      {/* Risk Breakdown */}
      {findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{
            fontSize: '0.78rem', fontWeight: 600,
            color: 'var(--text-muted)', marginBottom: 8,
            textTransform: 'uppercase', letterSpacing: '0.05em',
          }}>
            Risk Breakdown
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {Object.entries(riskCounts).map(([level, count]) =>
              count > 0 ? (
                <span key={level} className={`risk-badge ${level}`}>
                  {count} {level}
                </span>
              ) : null
            )}
          </div>
        </div>
      )}

      {/* Detection Types */}
      {Object.keys(typeCounts).length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{
            fontSize: '0.78rem', fontWeight: 600,
            color: 'var(--text-muted)', marginBottom: 8,
            textTransform: 'uppercase', letterSpacing: '0.05em',
          }}>
            Detected Types
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(typeCounts).map(([type, count]) => (
              <span
                key={type}
                style={{
                  padding: '3px 10px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-glass)',
                  borderRadius: '12px',
                  fontSize: '0.72rem',
                  color: 'var(--text-secondary)',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {type} ({count})
              </span>
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
            <span className="insight-icon">⚠️</span>
            {insight}
          </li>
        ))}
      </ul>
    </div>
  );
}
