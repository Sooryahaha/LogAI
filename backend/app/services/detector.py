"""
Detector service — deterministic regex-based sensitive data and security issue detection.
No AI dependency. All detection is rule-based and explainable.
"""

from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    RISK_MAP,
    SECURITY_PATTERNS,
    SENSITIVE_PATTERNS,
)


class Detector:
    """
    Deterministic detection engine using compiled regex patterns.
    Produces Finding objects with type, risk, and line number.
    """

    def detect(self, content: str) -> list[Finding]:
        """
        Scan content line-by-line for sensitive data and security issues.
        Returns a de-duplicated list of Finding objects.
        """
        logger.info("Starting deterministic detection scan")
        findings: list[Finding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            # Check sensitive data patterns
            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                if pattern.search(line):
                    risk = RISK_MAP.get(pattern_name, "medium")
                    finding = Finding(type=pattern_name, risk=risk, line=line_num)
                    if not self._is_duplicate(findings, finding):
                        findings.append(finding)
                        logger.debug(
                            f"Detected {pattern_name} (risk={risk}) at line {line_num}"
                        )

            # Check security issue patterns
            for pattern_name, pattern in SECURITY_PATTERNS.items():
                if pattern.search(line):
                    risk = RISK_MAP.get(pattern_name, "medium")
                    finding = Finding(type=pattern_name, risk=risk, line=line_num)
                    if not self._is_duplicate(findings, finding):
                        findings.append(finding)
                        logger.debug(
                            f"Detected {pattern_name} (risk={risk}) at line {line_num}"
                        )

        logger.info(f"Detection complete: {len(findings)} findings")
        return findings

    @staticmethod
    def _is_duplicate(findings: list[Finding], new_finding: Finding) -> bool:
        """Check if this exact finding already exists."""
        return any(
            f.type == new_finding.type
            and f.line == new_finding.line
            for f in findings
        )
