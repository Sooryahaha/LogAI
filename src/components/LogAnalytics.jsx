import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';

/**
 * LogAnalytics — Enhanced Log Visualization Panel
 * Features:
 * 1. Bar chart of findings by RISK level.
 * 2. Pie chart of findings by TYPE.
 * 3. Stats counters for Entities (IPs, Users, Resources).
 */
export default function LogAnalytics({ data }) {
  if (!data) return null;

  const { findings = [], ai_findings = [], security_graph, risk_level, risk_score } = data;
  const allFindings = [...findings, ...ai_findings];

  // ── Prepare Disk Data ───────────────────────────────────────────────────
  const riskCounts = allFindings.reduce((acc, f) => {
    acc[f.risk] = (acc[f.risk] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const riskData = [
    { name: 'Critical', value: riskCounts.critical, color: '#FFFFFF' },
    { name: 'High', value: riskCounts.high, color: '#AAAAAA' },
    { name: 'Medium', value: riskCounts.medium, color: '#666666' },
    { name: 'Low', value: riskCounts.low, color: '#333333' },
  ].filter(d => d.value > 0 || allFindings.length === 0);

  // If no findings, add a placeholder for the risk level
  if (riskData.length === 0) {
    riskData.push({ name: risk_level || 'Low', value: 1, color: '#333' });
  }

  // ── Prepare Type Data ───────────────────────────────────────────────────
  const typeCounts = allFindings.reduce((acc, f) => {
    const type = f.type?.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') || 'Unknown';
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});

  let typeData = Object.entries(typeCounts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  if (typeData.length === 0) {
    typeData = [{ name: 'System Stable', value: 100 }];
  }

  const PIE_COLORS = ['#FFFFFF', '#CCCCCC', '#999999', '#666666', '#333333'];

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="glass-card slide-up log-analytics-panel">
      <div className="card-title">FORENSIC LOG ANALYTICS</div>

      {/* Stats row */}
      <div className="analytics-stats-row">
        <div className="analytics-stat">
          <span className="label">VECTORED IPs</span>
          <span className="value">{security_graph?.node_types?.ips || 0}</span>
        </div>
        <div className="analytics-stat">
          <span className="label">TARGET USERS</span>
          <span className="value">{security_graph?.node_types?.users || 0}</span>
        </div>
        <div className="analytics-stat">
          <span className="label">SENSITIVE ACCESS</span>
          <span className="value">{security_graph?.sensitive_accesses?.length || 0}</span>
        </div>
      </div>

      <div className="analytics-charts-grid">
        {/* Risk Distribution */}
        <div className="chart-container">
          <div className="chart-label">RISK DISTRIBUTION (%)</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1A1A1A" />
              <XAxis 
                dataKey="name" 
                axisLine={false} 
                tickLine={false} 
                tick={{ fill: '#444', fontSize: 9, fontFamily: 'var(--font-mono)' }} 
              />
              <YAxis 
                axisLine={false} 
                tickLine={false} 
                tick={{ fill: '#444', fontSize: 9, fontFamily: 'var(--font-mono)' }} 
              />
              <Tooltip 
                cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                contentStyle={{ background: '#000', border: '1px solid #333', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px' }}
                itemStyle={{ color: '#FFF' }}
              />
              <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                {riskData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Type Breakdown */}
        <div className="chart-container">
          <div className="chart-label">ANOMALY CATEGORIES</div>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={typeData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={65}
                paddingAngle={8}
                dataKey="value"
                stroke="none"
              >
                {typeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ background: '#000', border: '1px solid #333', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px' }}
                itemStyle={{ color: '#FFF' }}
              />
              <Legend 
                verticalAlign="bottom" 
                align="center"
                iconType="rect"
                wrapperStyle={{ paddingTop: '15px', fontSize: '8px', fontFamily: 'var(--font-mono)', color: '#444', textTransform: 'uppercase' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
