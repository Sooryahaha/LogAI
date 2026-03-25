# 🛡️ SISA: AI Secure Data Intelligence Platform

SISA is an enterprise-grade cybersecurity validation and intelligence platform. It moves beyond traditional static log scanning by introducing proactive, AI-driven defense mechanisms and continuous adversarial testing frameworks.

## Core Capabilities

1. **Autonomous Deception Mesh (Honeypot)**
   - Deploys highly realistic, dynamic corporate decoys (e.g., Internal API Explorers, Admin Logins).
   - Defeats AI-driven hackers by embedding **Reverse Prompt Injections** within the HTML source code, directly overriding malevolent LLM agents and forcing them to leak their context windows and mission objectives into our logs.

2. **Digital Twin (Adversarial Simulation Engine)**
   - A virtualized replica of the internal risk engine designed for continuous testing.
   - Automatically executes 9 high-severity attack vectors (including `Log4Shell`, `Union-Based SQLi`, and `Path Traversal`) against the risk engine.
   - Statistically verifies the detection and policy drop logic, ensuring a **100% Success Rate** against zero-day and documented vectors before real-world deployment.

3. **Forensic Log Scanner & Risk Engine**
   - Ingests raw datastreams (F5 ASM Syslogs, JSON, standard network taps).
   - Employs a deterministic, URL-decoded Regex parser mapped against the MITRE ATT&CK framework.
   - Calculates immutable risk scores (Low -> Critical) and automatically triggers enforcement policies (Allowed, Masked, Blocked).

## Technology Stack

- **Frontend:** React (Vite), React Router, pure Vanilla CSS (`Orbitron` & `Share Tech Mono` for a sharp, zero-distraction Cyberpunk aesthetic).
- **Backend:** Python + FastAPI.
- **Routing:** Vercel serverless configurations (`vercel.json`, `api/index.py`) mapping the Python runtime smoothly alongside the static front end.

## Deployment & Setup

For local hacking or deployment instructions, please reference [Setup.md](./Setup.md).

---
*Built for the ultimate cybersecurity presentation.*
