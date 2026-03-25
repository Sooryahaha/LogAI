# Project Write-Up: LogAI (Secure Data Intelligence)

## 🛡️ The Problem Solved
In modern DevOps and development, **unstructured data**—logs, chat messages, SQL queries, and internal documents—is a primary source of sensitive data leakage. Developers often accidentally log passwords, API keys, or stack traces that reveal system internals. **LogAI** solves this by providing a unified, high-performance platform to ingest, analyze, and neutralize these risks before they reach persistent storage or public repositories.

## 🏗️ Approach and Design
LogAI is built on a **Modular Security Pipeline** architecture:
1.  **Deterministic Detection**: We use a refined library of regex patterns to ensure that critical leaks (API keys, passwords, Tokens) are caught with 100% reliability and zero "AI hallucinations."
2.  **Contextual Analysis**: Our [LogAnalyzer](file:///Users/sooryapersonal/Desktop/asdip/backend/app/services/log_analyzer.py#20-144) goes beyond keywords, performing cross-line correlation to detect behavioral threats like brute-force attacks and suspicious IP spikes.
3.  **Privacy-First AI**: We integrate **Ollama** (Llama3) locally. This allows us to provide human-readable security summaries and remediation steps without ever sending sensitive raw data to the cloud.
4.  **Policy-Driven UX**: The platform doesn't just "show" risks; it applies policies (Masking/Blocking) based on a weighted risk scoring system, making it an active defense tool.

## 🛠️ Technologies Used
- **Backend**: FastAPI (Python) for an asynchronous, high-throughput API.
- **Frontend**: React + Vite for a high-performance, "Cyber Security" themed dashboard.
- **AI/ML**: Ollama (Local LLM) for intelligent security insights.
- **Data Handling**: PyPDF2 and Python-Docx for multi-source document ingestion.
- **Infrastructure**: Docker & Nginx for robust, portable deployment.

## 🚧 Challenges Faced
- **Performance vs. Depth**: Scanning 100,000+ lines of logs line-by-line can be slow. We implemented a **Chunked Processing** strategy in our [LogAnalyzer](file:///Users/sooryapersonal/Desktop/asdip/backend/app/services/log_analyzer.py#20-144) to maintain UI responsiveness while performing deep correlation.
- **AI Fallback Logic**: Ensuring the platform remains useful even if the local LLM is unavailable was critical. We built a twin-track system that switches to rule-based templates if the Ollama service times out.
- **Aesthetic Precision**: Creating a "Cyber Security" feel that wasn't distracting required careful balance of scanline effects, glassmorphism, and monochromatic typography.

## 🚀 The Result
LogAI is a production-ready security gate that empowers teams to handle unstructured data with confidence, combining the speed of traditional regex with the reasoning of modern AI.
