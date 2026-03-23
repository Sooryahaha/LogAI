# LogAI: Secure Data Intelligence Platform

LogAI is a high-performance, modular security tool designed to detect sensitive data leaks, security risks, and brute-force patterns in multi-source content. It specifically focuses on logs, SQL queries, and text inputs to prevent accidental exposure of credentials and system details.

---

## 🚀 Key Features

- **Multi-Source Ingestion:** Supports raw text, log files, SQL queries, and chat messages.
- **Deterministic Detection:** Uses compiled regex patterns for high-speed, explainable, and reliable detection without LLM hallucinations.
- **Deep Log Analysis:** Detects brute-force attacks (5+ failures), suspicious IP activity, and error leaks.
- **Weighted Risk Scoring:** Assigns risk levels (Low, Medium, High, Critical) based on the severity of the leak.
- **Intelligent Insights:** Generates actionable remediation steps using a local LLM (Ollama) with a robust rule-based fallback.
- **Security Policies:** Automatically applies "Mask" or "Block" actions based on risk thresholds.

---

## 📂 Core Logic Breakdown (Line-by-Line)

### 1. `backend/app/api/analyze.py` (The Orchestrator)
This is the main entry point for the analysis pipeline.

- **Lines 21-26:** Initializes all singleton services: `Parser`, `Detector`, `LogAnalyzer`, `RiskEngine`, `PolicyEngine`, and `InsightEngine`.
- **Line 30:** Defines the `POST /analyze` endpoint.
- **Line 39:** `is_potentially_malicious` checks for null bytes or control characters in the input to prevent injection attacks on the analyzer itself.
- **Line 44:** The `parser.parse` method normalizes different inputs (PDF, DOCX, Log, Text) into a standard string format.
- **Line 49:** `detector.detect` runs the core regex scan to find emails, API keys, passwords, etc.
- **Lines 54-69:** If the input is a log, the `LogAnalyzer` runs cross-line correlation for brute-force and IP tracking, then merges these findings with the detector results.
- **Line 72:** `risk_engine.calculate` aggregates all findings into a single risk score (0-100) and a categorical level (Low to Critical).
- **Line 78:** `policy_engine.apply` decides the final action (allowed, masked, or blocked) based on user options and risk level.
- **Line 89:** `insight_engine.generate` produces the "summary" and "insights" array. It tries to use Ollama for natural language, falling back to deterministic templates if Ollama is offline.

---

### 2. `backend/app/services/detector.py` (The Scanner)
Responsible for finding sensitive patterns within individual lines.

- **Lines 21-25:** The `detect` method splits content by newline to preserve line number accuracy for the UI.
- **Lines 35-43:** Iterates through `SENSITIVE_PATTERNS` (emails, phones, etc.) and records line numbers.
- **Lines 46-54:** Iterates through `SECURITY_PATTERNS` (stack traces, debug leaks, SQL injection).
- **Lines 60-66:** `_is_duplicate` ensures we don't report the same finding type on the same line multiple times, keeping the output clean.

---

### 3. `backend/app/utils/patterns.py` (The Brain)
Contains the regular expressions that drive the entire detection.

- **Line 10:** `EMAIL_PATTERN` matches standard RFC-compliant email addresses.
- **Line 20:** `API_KEY_PATTERN` detects AWS keys, generic `sk-` keys (8+ chars), and `access_key`.
- **Line 30:** `PASSWORD_PATTERN` looks for assignments like `password=...` but excludes short strings to avoid false positives.
- **Line 35:** `TOKEN_PATTERN` catches JWTs and Bearer tokens.
- **Line 50:** `STACK_TRACE_PATTERN` identifies Java/Python error fragments that reveal file paths or internal logic.
- **Line 57:** `DEBUG_MODE_PATTERN` flags when debug logging is enabled in production logs.
- **Line 70:** `FAILED_LOGIN_PATTERN` identifies authentication failure strings (401, unauthorized, etc.).
- **Line 130:** `RISK_MAP` defines the "cost" of each finding (e.g., `password` is `"critical"`, `email` is `"low"`).

---

### 4. `backend/app/services/log_analyzer.py` (The Auditor)
Handles logic that requires "state" across multiple lines.

- **Line 31:** `BRUTE_FORCE_THRESHOLD` is set to 5.
- **Lines 61-68:** Collects failed login attempts into a list.
- **Lines 99-111:** If the count exceeds the threshold, it marks a `brute_force` finding at the exact line where the threshold was triggered.
- **Lines 114-127:** Tracks IP addresses and flags any IP appearing more than 10 times as a `suspicious_ip`.
- **Line 129:** Generates a stats dictionary with totals for the response dashboard.

---

## 🧪 Verified Test Scenarios

The following scenarios were verified using `run_tests.py` and matched the expected security outputs:

### Scenario 1: Basic Sensitive Data Leak
**Input:** Log with email, password, and API key.
**Result:** Detected All 3. `Risk: High`, `Action: Masked`.

### Scenario 2: Stack Trace + Error Leak
**Input:** Single Java exception and debug stack trace.
**Result:** Detected `stack_trace` and `debug_leak`. `Risk: Medium`.

### Scenario 3: Brute Force Detection
**Input:** 5 consecutive "login failed" messages.
**Result:** Detected `brute_force`. `Risk: Critical`.

---

## 🛠️ Setup Instructions

### Backend
1. `cd backend`
2. `python -m venv venv && source venv/bin/activate`
3. `pip install -r requirements.txt`
4. `uvicorn app.main:app --port 8000`

### Frontend (Optional)
1. `cd frontend`
2. `npm install && npm run dev`

---

Built with ❤️ for Security Professionals.
