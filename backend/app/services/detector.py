"""
Detector service — deterministic detection with URL-decode preprocessing,
F5 ASM structured log parsing, and compound WAF bypass detection.
"""

import re
from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    RISK_MAP,
    SECURITY_PATTERNS,
    SENSITIVE_PATTERNS,
    NETWORK_PATTERNS,
    F5_ASM_PATTERN,
    WAF_BYPASS_PATTERN,
    XSS_PATTERN,
    url_decode_content,
)


class Detector:
    """
    Deterministic detection engine using compiled regex patterns.
    Applies URL-decode preprocessing so encoded payloads are always caught.
    Includes F5 ASM compound finding logic.
    """

    def detect(self, content: str, input_type: str = "log") -> list[Finding]:
        """
        Scan content for sensitive data and security issues.
        Returns a de-duplicated list of Finding objects.
        """
        logger.info(f"Starting deterministic detection scan (type={input_type})")
        findings: list[Finding] = []
        lines = content.split("\n")

        # Check if this looks like F5 ASM structured log
        is_f5_asm = any(F5_ASM_PATTERN.search(line) for line in lines if line.strip())

        for line_num, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            # URL-decode the line for encoded payload detection
            decoded_line = url_decode_content(line)

            # Run all sensitive + security patterns on both raw and decoded line
            scan_targets = {line, decoded_line}

            for scan_line in scan_targets:
                for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                    if pattern.search(scan_line):
                        risk = RISK_MAP.get(pattern_name, "medium")
                        finding = Finding(type=pattern_name, risk=risk, line=line_num)
                        if not self._is_duplicate(findings, finding):
                            findings.append(finding)

                for pattern_name, pattern in SECURITY_PATTERNS.items():
                    if pattern.search(scan_line):
                        risk = RISK_MAP.get(pattern_name, "medium")
                        finding = Finding(type=pattern_name, risk=risk, line=line_num)
                        if not self._is_duplicate(findings, finding):
                            findings.append(finding)

            # Network packet patterns
            if input_type == "network":
                for pattern_name, pattern in NETWORK_PATTERNS.items():
                    if pattern.search(line):
                        risk = RISK_MAP.get(pattern_name, "high")
                        finding = Finding(type=pattern_name, risk=risk, line=line_num)
                        if not self._is_duplicate(findings, finding):
                            findings.append(finding)

        # ── Brute Force Aggregation ──────────────────────────────────────────────────
        failed_login_count = 0
        from app.utils.patterns import LOG_PATTERNS
        for line in lines:
            if LOG_PATTERNS["failed_login"].search(line):
                failed_login_count += 1
        
        if failed_login_count >= 5:
            findings.append(Finding(type="brute_force", risk="critical", line=1))
            logger.warning(f"Brute force detected: {failed_login_count} failed logins")

        # ── F5 ASM Compound Finding ───────────────────────────────────────────
        # Detect WAF bypass: request_status=passed + violation_rating >= 4 + XSS in URI
        if is_f5_asm:
            f5_findings = self._analyze_f5_asm(lines)
            for f in f5_findings:
                if not self._is_duplicate(findings, f):
                    findings.append(f)

        logger.info(f"Detection complete: {len(findings)} findings")
        return findings

    def _analyze_f5_asm(self, lines: list[str]) -> list[Finding]:
        """
        Compound detection for F5 BIG-IP ASM logs.
        Looks for: passed status + high violation rating + dangerous URI/staged sigs.
        """
        findings = []
        full_text = "\n".join(lines)

        # Extract key fields
        status_match = re.search(r'request_status="(\w+)"', full_text, re.IGNORECASE)
        rating_match = re.search(r'violation_rating="(\d+)"', full_text, re.IGNORECASE)
        staged_sigs_match = re.search(r'staged_sig_names="([^"]+)"', full_text, re.IGNORECASE)
        uri_match = re.search(r'uri="([^"]+)"', full_text, re.IGNORECASE)

        request_status = status_match.group(1) if status_match else ""
        violation_rating = int(rating_match.group(1)) if rating_match else 0
        staged_sigs = staged_sigs_match.group(1) if staged_sigs_match else "N/A"
        uri = uri_match.group(1) if uri_match else ""

        # WAF Bypass: request passed but has high violation rating
        if request_status.lower() == "passed" and violation_rating >= 4:
            findings.append(Finding(type="waf_bypass", risk="critical", line=1))
            logger.warning(
                f"F5 ASM WAF bypass detected: status=passed, violation_rating={violation_rating}"
            )

        # Staged signatures that fired (unblocked threats)
        if staged_sigs and staged_sigs.upper() != "N/A":
            sig_list = [s.strip() for s in staged_sigs.split(",") if s.strip()]
            for sig in sig_list:
                if re.search(r"(?:xss|script|inject|traversal|sqli)", sig, re.IGNORECASE):
                    findings.append(Finding(type="xss", risk="critical", line=1))
                    break

        # Dangerous URI with XSS payload
        if uri and (XSS_PATTERN.search(url_decode_content(uri)) or "<script" in url_decode_content(uri).lower()):
            findings.append(Finding(type="xss", risk="critical", line=1))

        return findings

    @staticmethod
    def _is_duplicate(findings: list[Finding], new_finding: Finding) -> bool:
        return any(
            f.type == new_finding.type and f.line == new_finding.line
            for f in findings
        )
