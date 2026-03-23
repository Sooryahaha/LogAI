/**
 * LogViewer — displays log content line-by-line with risk highlighting.
 * Flags lines that have findings and shows risk badges.
 */
export default function LogViewer({ content, findings }) {
  if (!content) return null;

  const lines = content.split('\n');

  // Build a map: line_number -> [findings]
  const findingsMap = {};
  for (const f of findings) {
    if (!findingsMap[f.line]) findingsMap[f.line] = [];
    findingsMap[f.line].push(f);
  }

  const getLineClass = (lineFindings) => {
    if (!lineFindings) return 'log-line';
    const risks = lineFindings.map((f) => f.risk);
    if (risks.includes('critical')) return 'log-line flagged-critical';
    if (risks.includes('high')) return 'log-line flagged';
    if (risks.includes('medium')) return 'log-line flagged-medium';
    return 'log-line flagged-low';
  };

  const getBadgeClass = (risk) => {
    const map = {
      critical: 'risk-badge critical',
      high: 'risk-badge high',
      medium: 'risk-badge medium',
      low: 'risk-badge low',
    };
    return map[risk] || 'risk-badge low';
  };

  return (
    <div className="glass-card slide-up">
      <div className="card-title">
        <span className="icon"></span>
        LOG VIEWER
        <span style={{ marginLeft: 'auto', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          {lines.length} lines · {findings.length} findings
        </span>
      </div>
      <div className="log-viewer" id="log-viewer">
        {lines.map((line, idx) => {
          const lineNum = idx + 1;
          const lineFindings = findingsMap[lineNum];
          return (
            <div key={idx} className={getLineClass(lineFindings)}>
              <span className="line-number">{lineNum}</span>
              <span className="line-content">{line || ' '}</span>
              <div className="line-badges">
                {lineFindings &&
                  lineFindings.map((f, i) => (
                    <span key={i} className={`line-badge ${getBadgeClass(f.risk)}`}>
                      {f.type}
                    </span>
                  ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
