import { useState, useRef } from 'react';

const INPUT_TYPES = [
  { key: 'log', label: '📋 Log', desc: 'Analyze log files' },
  { key: 'text', label: '📝 Text', desc: 'Analyze plain text' },
  { key: 'file', label: '📁 File', desc: 'Upload a file' },
  { key: 'sql', label: '🗃️ SQL', desc: 'Analyze SQL queries' },
  { key: 'chat', label: '💬 Chat', desc: 'Analyze chat messages' },
];

const TEST_SCENARIOS = [
  {
    id: 'basic',
    name: '🔒 Basic Leak',
    type: 'log',
    content: `2026-03-10 10:00:01 INFO User login\nemail=admin@company.com\npassword=admin123\napi_key=sk-prod-xyz`
  },
  {
    id: 'stack',
    name: '🛠️ Stack Trace',
    type: 'log',
    content: `2026-03-10 ERROR NullPointerException at service.java:45\nDEBUG stack trace: line 45 -> service failed`
  },
  {
    id: 'brute',
    name: '🛡️ Brute Force',
    type: 'log',
    content: `2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin`
  },
  {
    id: 'token',
    name: '🔑 Token Exposure',
    type: 'log',
    content: `INFO token=abc123xyz\nINFO api_key=sk-test-987654`
  },
  {
    id: 'clean',
    name: '✅ Clean Log',
    type: 'log',
    content: `2026-03-10 INFO Server started successfully\n2026-03-10 INFO Health check passed`
  },
  {
    id: 'mixed',
    name: '🎭 Mixed Case',
    type: 'log',
    content: `2026-03-10 INFO User login\nemail=user@test.com\npassword=pass123\n2026-03-10 ERROR Exception at controller.java:22\nDEBUG mode enabled\ntoken=xyz-token-123`
  }
];

export default function InputPanel({ onAnalyze, isLoading }) {
  const [inputType, setInputType] = useState('log');
  const [content, setContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [dragging, setDragging] = useState(false);
  const [options, setOptions] = useState({
    mask: true,
    block_high_risk: true,
    log_analysis: true,
  });
  const fileInputRef = useRef(null);

  const handleFileRead = (file) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      // Split off the "data:application/pdf;base64," prefix to get pure base64
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
      options,
    });
  };

  const loadScenario = (scenario) => {
    setContent(scenario.content);
    setInputType(scenario.type);
    setFileName('');
  };

  const toggleOption = (key) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const placeholders = {
    log: 'Paste log content here...',
    text: 'Enter text to analyze for sensitive data...',
    file: 'File content will appear here after upload...',
    sql: 'Enter SQL query to analyze...',
    chat: 'Enter chat message to analyze...',
  };

  return (
    <div className="input-panel glass-card">
      <div className="card-title">
        <span className="icon">🔍</span>
        Input Analysis
      </div>

      {/* Type Selector */}
      <div className="type-selector">
        {INPUT_TYPES.map((t) => (
          <button
            key={t.key}
            className={`type-btn ${inputType === t.key ? 'active' : ''}`}
            onClick={() => setInputType(t.key)}
            title={t.desc}
            id={`type-btn-${t.key}`}
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
            id="file-drop-zone"
          >
            <div className="drop-icon">📂</div>
            <div className="drop-text">
              Drop a file here or click to upload
            </div>
            <div className="drop-hint">.log, .txt, .pdf, .doc supported</div>
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
            id="file-input"
          />
          {fileName && (
            <div className="file-name">
              📎 {fileName}
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
        id="content-textarea"
      />

      {/* Test Scenarios */}
      <div className="test-scenarios">
        <div style={{ fontSize: '0.75rem', opacity: 0.6, marginBottom: '8px' }}>Test Scenarios:</div>
        <div className="scenario-grid">
          {TEST_SCENARIOS.map((s) => (
            <button
              key={s.id}
              className="scenario-chip"
              onClick={() => loadScenario(s)}
              id={`scenario-btn-${s.id}`}
            >
              {s.name}
            </button>
          ))}
          <button
            className="scenario-chip clear"
            onClick={() => { setContent(''); setFileName(''); }}
            id="scenario-btn-clear"
          >
            🗑️ Clear
          </button>
        </div>
      </div>

      {/* Options */}
      <div className="options-group">
        <div className="option-toggle" onClick={() => toggleOption('mask')}>
          <span className="option-label">🔒 Mask sensitive data</span>
          <div className={`toggle-switch ${options.mask ? 'on' : ''}`} />
        </div>
        <div className="option-toggle" onClick={() => toggleOption('block_high_risk')}>
          <span className="option-label">🛡️ Block high risk</span>
          <div className={`toggle-switch ${options.block_high_risk ? 'on' : ''}`} />
        </div>
        <div className="option-toggle" onClick={() => toggleOption('log_analysis')}>
          <span className="option-label">📊 Deep log analysis</span>
          <div className={`toggle-switch ${options.log_analysis ? 'on' : ''}`} />
        </div>
      </div>

      {/* Analyze Button */}
      <button
        className="analyze-btn"
        onClick={handleSubmit}
        disabled={isLoading || !content.trim()}
        id="analyze-btn"
      >
        {isLoading ? (
          <><span className="spinner" /> Analyzing...</>
        ) : (
          '🚀 Analyze Content'
        )}
      </button>
    </div>
  );
}
