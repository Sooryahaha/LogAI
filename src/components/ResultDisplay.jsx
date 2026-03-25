/**
 * ResultDisplay — shows the findings table and raw JSON response.
 * Verifies the response matches the API contract visually.
 */
export default function ResultDisplay({ data }) {
  if (!data) return null;

  const { findings } = data;

  const getBadgeClass = (risk) => {
    return `risk-badge ${risk}`;
  };

  return (
    <div className="slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Findings Table */}
      {findings.length > 0 && (
        <div className="glass-card">
          <div className="card-title">
            FINDINGS
            <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)' }}>
              {findings.length} TOTAL
            </span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="findings-table" id="findings-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type</th>
                  <th>Risk</th>
                  <th>Line</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, idx) => (
                  <tr key={idx}>
                    <td style={{ color: 'var(--text-muted)' }}>{idx + 1}</td>
                    <td>
                      <span className="finding-type">{f.type}</span>
                    </td>
                    <td>
                      <span className={getBadgeClass(f.risk)}>{f.risk}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{f.line}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Raw JSON Response */}
      <div className="glass-card">
          <div className="card-title">API RESPONSE</div>
        <div className="json-display" id="json-display">
          <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
