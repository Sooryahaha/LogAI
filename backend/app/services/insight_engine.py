"""
Insight Engine — generates SISA forensic-grade security insights.
Uses Google Gemini LLM when available, falls back to deterministic rule-based generation.
"""

import json
from collections import Counter

from app.core.logging_config import logger
from app.models.schemas import Finding
from app.services.ai_client import AIClient


class InsightEngine:
    """
    Generates human-readable security insights from analysis findings.
    Two modes:
    1. AI-enhanced: Uses Google Gemini for SISA forensic intelligence reports
    2. Rule-based fallback: Deterministic insight generation from findings
    """

    def __init__(self):
        self.ai_client = AIClient()

    async def generate(
        self,
        content: str,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None = None,
    ) -> dict:
        """
        Generate summary, insights, and forensic report.
        Returns dict with 'summary', 'insights', and 'forensic_report' keys.
        """
        # Try AI-enhanced generation first
        ai_result = await self._try_ai_generation(
            content, findings, risk_score, risk_level, content_type, log_stats
        )
        if ai_result:
            return ai_result

        # Fall back to rule-based generation
        logger.info("Using rule-based insight generation")
        return self._rule_based_generation(
            findings, risk_score, risk_level, content_type, log_stats
        )

    async def _try_ai_generation(
        self,
        content: str,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None,
    ) -> dict | None:
        """Attempt to generate SISA forensic insights and AI findings using Google Gemini."""

        # Truncate content for sanity if it's enormous
        safe_content = content[:50000]

        # Build context for the LLM
        finding_summary = self._build_finding_summary(findings) if findings else "None detected by rules"
        stats_text = ""
        if log_stats:
            stats_text = (
                f"\nLog statistics: {log_stats['total_lines']} lines, "
                f"{log_stats['failed_logins']} failed logins, "
                f"{log_stats['error_leaks']} error leaks, "
                f"brute force detected: {log_stats['brute_force_detected']}"
            )

        prompt = (
            "You are SISA-01, an elite Cybersecurity Forensic Intelligence Agent for SISA Infosec. "
            "You provide Deep Anomaly Scanning on raw logs, files, network packets, and SQL. "
            "You detect zero-days, business logic bypasses, and context-based anomalies that strict regex rules miss.\n\n"
            f"Analyze this raw {content_type}:\n\n"
            f"--- START RAW CONTENT ---\n{safe_content}\n--- END RAW CONTENT ---\n\n"
            f"Pre-detected Rule/Regex Findings: {finding_summary}\n"
            f"Current Risk Score: {risk_score}/100 ({risk_level}){stats_text}\n\n"
            "Respond in this EXACT JSON format with NO markdown formatting, NO code fences:\n"
            "{\n"
            '  "summary": "One-sentence forensic summary of the incident",\n'
            '  "attack_narrative": "FIRST PERSON ATTACKER PERSPECTIVE: write a paragraph starting with \'I am a threat actor...\' explaining exactly what I did in this log, what vulnerability I was exploiting, and what my ultimate goal was. Make it sound ruthless and professional.",\n'
            '  "insights": ["insight 1", "insight 2", "insight 3"],\n'
            '  "ai_findings": [\n'
            '    {\n'
            '      "type": "Context-based Anomaly Name",\n'
            '      "risk": "medium or high or critical",\n'
            '      "line": 0,\n'
            '      "description": "Short explanation of the anomaly"\n'
            '    }\n'
            '  ],\n'
            '  "forensic_report": {\n'
            '    "status": "CRITICAL or WARNING or INFO",\n'
            '    "root_cause": "Technical explanation of why this occurred",\n'
            '    "patterns": [\n'
            '      {\n'
            '        "name": "Pattern name e.g. Repeated Failed Auth",\n'
            '        "evidence": "Specific log evidence or finding detail",\n'
            '        "mitre_tactic": "MITRE ATT&CK Tactic e.g. Credential Access",\n'
            '        "mitre_technique": "MITRE ATT&CK Technique ID e.g. T1110"\n'
            '      }\n'
            '    ],\n'
            '    "remediation": [\n'
            '      "Step 1: Immediate action",\n'
            '      "Step 2: Follow-up action"\n'
            '    ]\n'
            '  }\n'
            "}\n\n"
            "CONSTRAINTS:\n"
            "- Only include ai_findings if you detect highly suspicious behavior NOT already caught by the rules.\n"
            "- If ai_findings are returned, estimate the line number reasonably.\n"
            "- Map every pattern to a real MITRE ATT&CK technique\n"
            "- Be specific and clinical, not generic\n"
            "- Output ONLY valid JSON, no other text"
        )

        response = await self.ai_client.generate(prompt)
        if not response:
            return None

        # Parse AI response
        try:
            # Strip markdown code fences if present
            cleaned = response.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()

            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(cleaned[start:end])
                summary = parsed.get("summary", "")
                insights = parsed.get("insights", [])
                ai_findings = parsed.get("ai_findings", [])
                forensic_report = parsed.get("forensic_report", None)
                attack_narrative = parsed.get("attack_narrative", None)

                if summary and insights:
                    logger.info(f"Gemini forensic insights parsed successfully (AI findings: {len(ai_findings)})")
                    return {
                        "summary": summary,
                        "insights": insights[:5],
                        "ai_findings": ai_findings,
                        "forensic_report": forensic_report,
                        "attack_narrative": attack_narrative,
                    }
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to parse Gemini response: {e}")

        return None

    def _rule_based_generation(
        self,
        findings: list[Finding],
        risk_score: int,
        risk_level: str,
        content_type: str,
        log_stats: dict | None,
    ) -> dict:
        """Generate deterministic insights from findings."""
        if not findings:
            return {
                "summary": f"No security issues detected in {content_type} content",
                "insights": ["Content appears clean with no detected vulnerabilities"],
                "forensic_report": None,
            }

        # Count findings by type
        type_counts = Counter(f.type for f in findings)
        risk_counts = Counter(f.risk for f in findings)

        # Build summary
        summary_parts = []
        if "password" in type_counts or "secret" in type_counts:
            summary_parts.append("sensitive credentials exposed")
        if "api_key" in type_counts:
            summary_parts.append("API keys detected")
        if "token" in type_counts:
            summary_parts.append("authentication tokens found")
        if "stack_trace" in type_counts or "error_leak" in type_counts:
            summary_parts.append("error information leaked")
        if "debug_mode" in type_counts:
            summary_parts.append("debug mode enabled")
        if "brute_force" in type_counts:
            summary_parts.append("brute-force attack pattern detected")
        if "email" in type_counts:
            summary_parts.append("email addresses exposed")
        if "failed_login" in type_counts:
            summary_parts.append("failed login attempts detected")
        if "suspicious_ip" in type_counts:
            summary_parts.append("suspicious IP activity found")
        if "hardcoded_credential" in type_counts:
            summary_parts.append("hardcoded credentials in source")
        if "sql_injection" in type_counts:
            summary_parts.append("SQL injection patterns detected")

        if not summary_parts:
            summary_parts.append("security issues detected")

        content_label = content_type.replace("_", " ")
        summary = f"{content_label.capitalize()} contains {', '.join(summary_parts)}"

        # Build insights
        insights = []

        if risk_counts.get("critical", 0) > 0:
            insights.append(
                f"{risk_counts['critical']} critical-severity issues require immediate attention"
            )
        if risk_counts.get("high", 0) > 0:
            insights.append(
                f"{risk_counts['high']} high-risk findings should be remediated urgently"
            )

        if "password" in type_counts:
            insights.append("Passwords must be removed from logs and rotated immediately")
        if "api_key" in type_counts:
            insights.append("API keys should be revoked and replaced with vault-based secrets")
        if "token" in type_counts:
            insights.append("Exposed tokens should be invalidated and regenerated")
        if "hardcoded_credential" in type_counts:
            insights.append("Replace hardcoded credentials with environment variables or secrets manager")
        if "stack_trace" in type_counts or "error_leak" in type_counts:
            insights.append("Error details and stack traces should not be exposed in production")
        if "debug_mode" in type_counts:
            insights.append("Debug mode must be disabled in production environments")
        if "email" in type_counts:
            insights.append("Consider masking email addresses to comply with privacy regulations")

        # Log-specific insights
        if log_stats:
            if log_stats.get("brute_force_detected"):
                insights.append(
                    f"Brute-force pattern: {log_stats['failed_logins']} failed logins detected — implement rate limiting"
                )
            if log_stats.get("suspicious_ips", 0) > 0:
                insights.append(
                    f"{log_stats['suspicious_ips']} suspicious IPs detected — consider IP blocking"
                )
            if log_stats.get("error_leaks", 0) > 5:
                insights.append(
                    "High volume of error leaks suggests misconfigured error handling"
                )

        if "sql_injection" in type_counts:
            insights.append("SQL injection patterns found — use parameterized queries")

        # Ensure at least one insight
        if not insights:
            insights.append(
                f"{len(findings)} security findings detected with {risk_level} overall risk"
            )

        # Cap at 5 insights
        insights = insights[:5]

        # Build a rule-based forensic report
        forensic_report = self._build_rule_based_forensic(
            type_counts, risk_counts, risk_score, risk_level, log_stats
        )

        return {
            "summary": summary,
            "insights": insights,
            "ai_findings": [],
            "forensic_report": forensic_report,
        }

    @staticmethod
    def _build_rule_based_forensic(
        type_counts: Counter,
        risk_counts: Counter,
        risk_score: int,
        risk_level: str,
        log_stats: dict | None,
    ) -> dict:
        """Build a deterministic forensic report from findings data."""
        # Determine status
        if risk_level == "critical":
            status = "CRITICAL"
        elif risk_level == "high":
            status = "WARNING"
        else:
            status = "INFO"

        # Build root cause
        causes = []
        if "password" in type_counts or "secret" in type_counts:
            causes.append("credentials exposed in plaintext")
        if "brute_force" in type_counts:
            causes.append("brute-force attack pattern active")
        if "sql_injection" in type_counts:
            causes.append("SQL injection vectors present")
        if "error_leak" in type_counts or "stack_trace" in type_counts:
            causes.append("error handling misconfigured")
        if not causes:
            causes.append("multiple security policy violations detected")

        root_cause = "; ".join(causes).capitalize()

        # Build patterns with MITRE mapping
        mitre_map = {
            "brute_force": ("Credential Access", "T1110 — Brute Force"),
            "password": ("Credential Access", "T1552 — Unsecured Credentials"),
            "api_key": ("Credential Access", "T1552.001 — Credentials In Files"),
            "token": ("Credential Access", "T1528 — Steal Application Access Token"),
            "secret": ("Credential Access", "T1552 — Unsecured Credentials"),
            "sql_injection": ("Initial Access", "T1190 — Exploit Public-Facing Application"),
            "failed_login": ("Credential Access", "T1110 — Brute Force"),
            "suspicious_ip": ("Discovery", "T1046 — Network Service Discovery"),
            "error_leak": ("Discovery", "T1082 — System Information Discovery"),
            "stack_trace": ("Discovery", "T1082 — System Information Discovery"),
            "hardcoded_credential": ("Credential Access", "T1552.001 — Credentials In Files"),
            "debug_leak": ("Discovery", "T1082 — System Information Discovery"),
            "email": ("Collection", "T1114 — Email Collection"),
        }

        patterns = []
        for finding_type, count in type_counts.most_common(4):
            tactic, technique = mitre_map.get(finding_type, ("Unknown", "N/A"))
            patterns.append({
                "name": f"{finding_type.replace('_', ' ').title()} ({count}x)",
                "evidence": f"Detected {count} instance(s) of {finding_type.replace('_', ' ')}",
                "mitre_tactic": tactic,
                "mitre_technique": technique,
            })

        # Build remediation
        remediation = []
        if "password" in type_counts or "secret" in type_counts:
            remediation.append("Rotate all exposed credentials immediately and purge from logs")
        if "api_key" in type_counts:
            remediation.append("Revoke compromised API keys and migrate to vault-based secret management")
        if "brute_force" in type_counts:
            remediation.append("Implement account lockout policy and rate limiting on auth endpoints")
        if "sql_injection" in type_counts:
            remediation.append("Deploy parameterized queries and input validation on all database interfaces")
        if "error_leak" in type_counts or "stack_trace" in type_counts:
            remediation.append("Configure production error handling to suppress stack traces and internal details")
        if not remediation:
            remediation.append("Review and remediate all flagged findings based on severity")

        return {
            "status": status,
            "root_cause": root_cause,
            "patterns": patterns,
            "remediation": remediation,
        }

    @staticmethod
    def _build_finding_summary(findings: list[Finding]) -> str:
        """Build a compact text summary of findings for the AI prompt."""
        type_counts = Counter(f.type for f in findings)
        parts = [f"{count}x {ftype}" for ftype, count in type_counts.items()]
        return ", ".join(parts)
