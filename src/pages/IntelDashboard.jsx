import { useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

/**
 * IntelDashboard Page
 * Contains the Honeypot and Digital Twin modules with enhanced visibility and explanations.
 */
export default function IntelDashboard() {
  const [activeTab, setActiveTab] = useState('honeypot');
  
  // Honeypot State
  const [hpLoading, setHpLoading] = useState(false);
  const [hpData, setHpData] = useState(null);
  const [hpError, setHpError] = useState('');
  const [hpTarget, setHpTarget] = useState('login');
  const [hpAsset, setHpAsset] = useState('CorpNet');

  // Twin State
  const [twinLoading, setTwinLoading] = useState(false);
  const [twinData, setTwinData] = useState(null);
  const [twinError, setTwinError] = useState('');

  const generateHoneypot = async () => {
    setHpLoading(true); setHpError(''); setHpData(null);
    try {
      const res = await axios.post('/api/honeypot', { target_type: hpTarget, asset_name: hpAsset });
      setHpData(res.data);
    } catch (err) {
      setHpError(err.response?.data?.detail || err.message || 'Failed to generate honeypot');
    } finally {
      setHpLoading(false);
    }
  };

  const runSimulation = async () => {
    setTwinLoading(true); setTwinError(''); setTwinData(null);
    try {
      const res = await axios.post('/api/twin/simulate', { attack_types: ['all'] });
      setTwinData(res.data);
    } catch (err) {
      setTwinError(err.response?.data?.detail || err.message || 'Simulation failed');
    } finally {
      setTwinLoading(false);
    }
  };

  return (
    <div className="app intel-dashboard-page" style={{ padding: '0 24px', maxWidth: '1400px', margin: '0 auto' }}>
      
      {/* ── Page Header ── */}
      <header className="header" style={{ marginBottom: 40 }}>
        <div className="header-left">
          <h1>SISA INTELLIGENCE DASHBOARD</h1>
          <p className="subtitle" style={{ fontSize: '0.9rem' }}>Deception Mesh & Adversarial Simulation Engine</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Link to="/" className="badge" style={{ textDecoration: 'none', padding: '10px 16px', fontSize: '0.8rem', cursor: 'pointer', transition: 'all 0.2s', border: '1px solid var(--border)' }}>
            ← BACK TO SCANNER
          </Link>
        </div>
      </header>

      {/* ── Main Container ── */}
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: '75vh' }}>
        
        {/* ── Tabs ── */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
          <button
            onClick={() => setActiveTab('honeypot')}
            style={{
              flex: 1, padding: '24px', background: activeTab === 'honeypot' ? 'var(--bg-elevated)' : 'transparent',
              border: 'none', borderBottom: activeTab === 'honeypot' ? '3px solid var(--text-primary)' : '3px solid transparent',
              color: activeTab === 'honeypot' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontFamily: 'var(--font-display)', fontSize: '1rem', fontWeight: 800, letterSpacing: '0.15em',
              textTransform: 'uppercase', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            Deception Mesh (Honeypot)
          </button>
          <button
            onClick={() => setActiveTab('twin')}
            style={{
              flex: 1, padding: '24px', background: activeTab === 'twin' ? 'var(--bg-elevated)' : 'transparent',
              border: 'none', borderBottom: activeTab === 'twin' ? '3px solid var(--text-primary)' : '3px solid transparent',
              color: activeTab === 'twin' ? 'var(--text-primary)' : 'var(--text-muted)',
              fontFamily: 'var(--font-display)', fontSize: '1rem', fontWeight: 800, letterSpacing: '0.15em',
              textTransform: 'uppercase', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            Digital Twin (Simulation)
          </button>
        </div>

        <div style={{ padding: '40px' }}>
          
          {/* ════════════════════════════════════════════════════════════════════════════ */}
          {/* ── HONEYPOT TAB ── */}
          {activeTab === 'honeypot' && (
            <div className="fade-in">
              
              {/* Explanation Panel */}
              <div style={{ background: 'var(--bg-secondary)', borderLeft: '4px solid var(--text-primary)', padding: '20px 24px', marginBottom: 32, borderRadius: '0 var(--r-md) var(--r-md) 0' }}>
                <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: 12, letterSpacing: '0.1em' }}>
                  HOW IT WORKS: AUTONOMOUS DECEPTION MESH
                </h3>
                <p style={{ fontFamily: 'var(--font-main)', fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
                  The <strong>Deception Mesh</strong> acts as a proactive defense mechanism (a "Honeypot"). Instead of waiting for an attacker, it actively deploys fake, high-fidelity corporate assets (like an Admin Login portal or Internal API). 
                  When automated vulnerability scanners or malicious AI agents interact with this fake portal, two things happen:
                </p>
                <ul style={{ fontFamily: 'var(--font-main)', fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.6, paddingLeft: 24, margin: 0 }}>
                  <li style={{ marginBottom: 6 }}><strong>Scanner Trapping:</strong> Security tooling will attack the fake login form, wasting resources and alerting the SoC to the attacker's IP.</li>
                  <li><strong>AI Prompt Injection:</strong> Hidden HTML comments contain <em>Reverse Prompt Injections</em>. If an LLM-powered attacking agent reads the page, the hidden instructions forcibly override its programming, causing it to leak its own context window, API keys, and mission objectives inside the logs.</li>
                </ul>
              </div>

              {/* Controls */}
              <div style={{ display: 'flex', gap: 16, marginBottom: 32, alignItems: 'center' }}>
                <select 
                  value={hpTarget} onChange={(e) => setHpTarget(e.target.value)}
                  style={{ padding: '14px 20px', background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.95rem', borderRadius: 'var(--r-md)', outline: 'none' }}
                >
                  <option value="login">Admin Login Portal</option>
                  <option value="admin">Management Console</option>
                  <option value="api">Internal API Explorer</option>
                </select>
                <input 
                  type="text" value={hpAsset} onChange={(e) => setHpAsset(e.target.value)}
                  placeholder="Asset/Corp Name (e.g. CorpNet)"
                  style={{ width: '300px', padding: '14px 20px', background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.95rem', borderRadius: 'var(--r-md)', outline: 'none' }}
                />
                <button 
                  onClick={generateHoneypot} disabled={hpLoading}
                  style={{ padding: '14px 32px', background: 'var(--text-primary)', color: 'var(--bg-base)', border: 'none', borderRadius: 'var(--r-md)', fontFamily: 'var(--font-display)', fontSize: '0.9rem', fontWeight: 800, letterSpacing: '0.1em', cursor: hpLoading ? 'not-allowed' : 'pointer', transition: 'all 0.2s' }}
                >
                  {hpLoading ? 'DEPLOYING INTELLIGENT BAIT...' : 'DEPLOY INTELLIGENT BAIT'}
                </button>
              </div>

              {hpError && <div className="error-message" style={{ marginBottom: 24, fontSize: '1rem', padding: '16px' }}>{hpError}</div>}

              {/* Results */}
              {hpData && (
                <div className="slide-up">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 32 }}>
                    
                    {/* Generated HTML Code */}
                    <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '24px', display: 'flex', flexDirection: 'column' }}>
                      <div className="section-label" style={{ fontSize: '0.85rem', marginBottom: 16 }}>GENERATED DECEPTION PAYLOAD (HTML SOURCE)</div>
                      <div style={{ flex: 1, background: '#0a0a0a', border: '1px solid var(--border-bright)', borderRadius: 'var(--r-sm)', padding: '20px', overflowY: 'auto', maxHeight: '500px' }}>
                        <pre style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#00ffcc', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.5 }}>
                          {hpData.honeypot_html}
                        </pre>
                      </div>
                    </div>

                    {/* Rendered View & AI Bait */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                      
                      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '24px' }}>
                        <div className="section-label" style={{ fontSize: '0.85rem', marginBottom: 16 }}>ACTIVE PROMPT INJECTIONS (AI BAIT EMBEDDED)</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                          {hpData.bait_strings.map((str, i) => (
                            <div key={i} style={{ padding: '12px 16px', background: '#0a0a0a', borderLeft: '3px solid var(--text-primary)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                              {str}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* IFrame Preview */}
                      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '24px', flex: 1 }}>
                        <div className="section-label" style={{ fontSize: '0.85rem', marginBottom: 16 }}>VISUAL DECOY PREVIEW (WHAT THE ATTACKER SEES)</div>
                        <div style={{ position: 'relative', width: '100%', height: '300px', background: '#000', borderRadius: 'var(--r-sm)', overflow: 'hidden', border: '1px solid var(--border)' }}>
                          <iframe 
                            srcDoc={hpData.honeypot_html}
                            style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', border: 'none' }}
                            title="Honeypot Preview"
                          />
                        </div>
                      </div>

                    </div>
                  </div>
                </div>
              )}
            </div>
          )}


          {/* ════════════════════════════════════════════════════════════════════════════ */}
          {/* ── TWIN TAB ── */}
          {activeTab === 'twin' && (
            <div className="fade-in">
              
              {/* Explanation Panel */}
              <div style={{ background: 'var(--bg-secondary)', borderLeft: '4px solid var(--text-primary)', padding: '20px 24px', marginBottom: 32, borderRadius: '0 var(--r-md) var(--r-md) 0' }}>
                <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: 12, letterSpacing: '0.1em' }}>
                  HOW IT WORKS: DIGITAL TWIN SIMULATION
                </h3>
                <p style={{ fontFamily: 'var(--font-main)', fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
                  The <strong>Digital Twin</strong> is a virtualized copy of your network architecture used strictly for adversarial testing. It automatically fires simulated payloads (malicious traffic, XSS, SQLi, and Brute Force attempts) against the internal threat detection engines.
                </p>
                <ul style={{ fontFamily: 'var(--font-main)', fontSize: '0.95rem', color: 'var(--text-secondary)', lineHeight: 1.6, paddingLeft: 24, margin: 0 }}>
                  <li style={{ marginBottom: 6 }}><strong>Verification:</strong> It ensures that the AI Risk Engine and Policy Engine are correctly flagging and dropping highly critical attacks in real-time.</li>
                  <li><strong>Continuous Validation:</strong> By running this simulation, the SoC (Security Operations Center) guarantees the defensive posture works optimally before a real-world breach occurs.</li>
                </ul>
              </div>

              {/* Controls */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32, paddingBottom: 24, borderBottom: '1px solid var(--border)' }}>
                <div style={{ maxWidth: '60%' }}>
                  <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.2rem', color: 'var(--text-primary)', letterSpacing: '0.1em', marginBottom: 8 }}>SECURITY STACK VERIFICATION</h3>
                  <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Clicking the button below will map 9 diverse attack vectors—including Log4Shell, SSRF, and LFI—against the SISA core detection pipeline.
                  </p>
                </div>
                <button 
                  onClick={runSimulation} disabled={twinLoading}
                  style={{ padding: '16px 32px', background: 'var(--text-primary)', color: 'var(--bg-base)', border: 'none', borderRadius: 'var(--r-md)', fontFamily: 'var(--font-display)', fontSize: '0.9rem', fontWeight: 800, letterSpacing: '0.1em', cursor: twinLoading ? 'not-allowed' : 'pointer', transition: 'all 0.2s' }}
                >
                  {twinLoading ? 'EXECUTING ADVERSARIAL SIMULATION...' : 'RUN FULL ATTACK SIMULATION'}
                </button>
              </div>

              {twinError && <div className="error-message" style={{ marginBottom: 24, fontSize: '1rem', padding: '16px' }}>{twinError}</div>}

              {twinData && (
                <div className="slide-up">
                  
                  {/* Stats */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24, marginBottom: 32 }}>
                    <div className="stat-card" style={{ padding: '32px 16px' }}>
                      <div className="stat-value" style={{ fontSize: '2.5rem' }}>{twinData.total_scenarios}</div>
                      <div className="stat-label" style={{ fontSize: '0.85rem' }}>PAYLOADS INJECTED</div>
                    </div>
                    <div className="stat-card" style={{ padding: '32px 16px', borderColor: twinData.pass_rate === 100 ? 'var(--text-primary)' : 'var(--border)' }}>
                      <div className="stat-value" style={{ fontSize: '2.5rem', color: 'var(--text-primary)' }}>
                        {twinData.pass_rate}%
                      </div>
                      <div className="stat-label" style={{ fontSize: '0.85rem' }}>SUCCESS RATE</div>
                    </div>
                    <div className="stat-card" style={{ padding: '32px 16px' }}>
                      <div className="stat-value" style={{ fontSize: '2.5rem' }}>{twinData.verified}</div>
                      <div className="stat-label" style={{ fontSize: '0.85rem' }}>THREATS MITIGATED</div>
                    </div>
                    <div className="stat-card" style={{ padding: '32px 16px' }}>
                      <div className="stat-value" style={{ fontSize: '2.5rem', color: twinData.failed > 0 ? '#FF4444' : 'var(--text-muted)' }}>{twinData.failed}</div>
                      <div className="stat-label" style={{ fontSize: '0.85rem' }}>STACK FAILURES</div>
                    </div>
                  </div>

                  {/* Simulation Feed */}
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', overflow: 'hidden' }}>
                    <div className="section-label" style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', margin: 0, fontSize: '0.9rem', background: '#0a0a0a' }}>
                      EVENT PIPELINE LOG
                    </div>
                    <table className="findings-table" style={{ border: 'none', borderRadius: 0, width: '100%' }}>
                      <thead>
                        <tr>
                          <th style={{ padding: '16px 24px', fontSize: '0.85rem' }}>Attack Vector Executed</th>
                          <th style={{ padding: '16px 24px', fontSize: '0.85rem' }}>Payload Class</th>
                          <th style={{ padding: '16px 24px', fontSize: '0.85rem' }}>Engine Risk Score</th>
                          <th style={{ padding: '16px 24px', fontSize: '0.85rem' }}>System Action</th>
                          <th style={{ padding: '16px 24px', fontSize: '0.85rem', textAlign: 'right' }}>Verification</th>
                        </tr>
                      </thead>
                      <tbody>
                        {twinData.simulation_results.map((res, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: res.verified ? 'transparent' : 'rgba(255,0,0,0.05)' }}>
                            <td style={{ padding: '20px 24px', color: 'var(--text-primary)', fontSize: '0.9rem' }}>{res.scenario_name}</td>
                            <td style={{ padding: '20px 24px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{res.attack_type.toUpperCase()}</td>
                            <td style={{ padding: '20px 24px' }}><span className={`risk-badge ${res.expected_risk}`} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>{res.expected_risk}</span></td>
                            <td style={{ padding: '20px 24px' }}>
                              <span className={`action-badge ${res.actual_action}`} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
                                {res.actual_action}
                              </span>
                            </td>
                            <td style={{ padding: '20px 24px', textAlign: 'right' }}>
                              {res.verified ? (
                                <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 800, letterSpacing: '0.1em' }}>[ ✓ GUARD ACTIVE ]</span>
                              ) : (
                                <span style={{ color: '#FF4444', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 800, letterSpacing: '0.1em' }}>[ ✗ BREACHED ]</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                </div>
              )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
