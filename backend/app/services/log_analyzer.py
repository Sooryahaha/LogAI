"""
Log Analyzer — deep log analysis with brute-force detection,
suspicious IP tracking, error leak detection, and cross-line correlation.
"""

from collections import Counter, defaultdict

from app.core.config import settings
from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    ERROR_LEAK_PATTERN,
    FAILED_LOGIN_PATTERN,
    IP_ADDRESS_PATTERN,
    RISK_MAP,
    SUSPICIOUS_IP_INDICATORS,
)


class LogAnalyzer:
    """
    Advanced log analysis engine with:
    - Line-by-line parsing with line number preservation
    - Brute-force detection (repeated failed logins)
    - Suspicious IP activity tracking
    - Error leak detection
    - Chunked processing for large logs
    - Log summary generation
    """

    BRUTE_FORCE_THRESHOLD = 5  # N failed logins = brute force

    def analyze(self, content: str) -> dict:
        """
        Perform deep log analysis.
        Returns dict with findings, stats, and summary.
        """
        logger.info("Starting log analysis")
        lines = content.split("\n")
        total_lines = len(lines)

        # Chunk large logs
        chunk_size = settings.LOG_CHUNK_SIZE
        all_findings: list[Finding] = []
        failed_login_lines: list[int] = []
        ip_counter: Counter = Counter()
        ip_lines: dict[str, list[int]] = defaultdict(list)
        error_count = 0
        suspicious_lines: list[int] = []

        for chunk_start in range(0, total_lines, chunk_size):
            chunk_end = min(chunk_start + chunk_size, total_lines)
            chunk = lines[chunk_start:chunk_end]

            for offset, line in enumerate(chunk):
                line_num = chunk_start + offset + 1  # 1-indexed
                if not line.strip():
                    continue

                # Failed login detection
                if FAILED_LOGIN_PATTERN.search(line):
                    failed_login_lines.append(line_num)
                    finding = Finding(
                        type="failed_login",
                        risk=RISK_MAP.get("failed_login", "medium"),
                        line=line_num,
                    )
                    all_findings.append(finding)

                # IP address tracking
                ips = IP_ADDRESS_PATTERN.findall(line)
                for ip in ips:
                    # Skip common non-suspicious IPs
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        ip_counter[ip] += 1
                        ip_lines[ip].append(line_num)

                # Suspicious IP indicators
                if SUSPICIOUS_IP_INDICATORS.search(line):
                    suspicious_lines.append(line_num)
                    finding = Finding(
                        type="suspicious_ip",
                        risk=RISK_MAP.get("suspicious_ip", "high"),
                        line=line_num,
                    )
                    all_findings.append(finding)

                # Error leak detection
                if ERROR_LEAK_PATTERN.search(line):
                    error_count += 1
                    finding = Finding(
                        type="error_leak",
                        risk=RISK_MAP.get("error_leak", "medium"),
                        line=line_num,
                    )
                    all_findings.append(finding)

        # ── Brute-force detection (cross-line correlation) ────────────────
        if len(failed_login_lines) >= self.BRUTE_FORCE_THRESHOLD:
            logger.warning(
                f"Brute-force pattern detected: {len(failed_login_lines)} failed logins"
            )
            # Add brute-force finding at the line of the threshold occurrence
            brute_line = failed_login_lines[self.BRUTE_FORCE_THRESHOLD - 1]
            all_findings.append(
                Finding(
                    type="brute_force",
                    risk="critical",
                    line=brute_line,
                )
            )

        # ── Suspicious IP activity (high-frequency IPs) ──────────────────
        suspicious_ips = {
            ip: count for ip, count in ip_counter.items() if count >= 10
        }
        for ip, count in suspicious_ips.items():
            first_line = ip_lines[ip][0]
            all_findings.append(
                Finding(
                    type="suspicious_ip",
                    risk="high",
                    line=first_line,
                )
            )
            logger.warning(f"High-frequency IP {ip} seen {count} times")

        # ── Generate log summary stats ────────────────────────────────────
        stats = {
            "total_lines": total_lines,
            "failed_logins": len(failed_login_lines),
            "unique_ips": len(ip_counter),
            "suspicious_ips": len(suspicious_ips),
            "error_leaks": error_count,
            "brute_force_detected": len(failed_login_lines) >= self.BRUTE_FORCE_THRESHOLD,
        }

        logger.info(f"Log analysis complete: {len(all_findings)} findings, stats={stats}")

        return {
            "findings": all_findings,
            "stats": stats,
        }
