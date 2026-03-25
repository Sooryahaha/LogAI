"""
Policy Engine — auto-blocks on critical/high risk by default.
Applies masking when enabled.
"""

from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.masking import mask_content


class PolicyEngine:
    """
    Applies security policies to analyzed content.
    Critical and high risk findings are ALWAYS blocked; no toggle required.
    """

    AUTO_BLOCK_LEVELS = {"critical", "high"}

    def apply(
        self,
        content: str,
        findings: list[Finding],
        risk_level: str,
        mask: bool = False,
        block_high_risk: bool = True,  # Default True — always protect
    ) -> dict:
        """
        Apply policies and determine action.
        Returns dict with action and optionally modified content.
        """
        action = "allowed"
        modified_content = content

        # Auto-block on critical/high risk — always enforced
        has_auto_block_finding = any(f.risk in self.AUTO_BLOCK_LEVELS for f in findings)
        risk_requires_block = risk_level in self.AUTO_BLOCK_LEVELS

        if has_auto_block_finding or risk_requires_block:
            action = "blocked"
            logger.info(
                f"Policy: BLOCKED — risk_level={risk_level}, "
                f"auto_block_finding={has_auto_block_finding}"
            )

        # Apply masking if requested (on top of block if applicable)
        if mask:
            modified_content = mask_content(content)
            if action == "allowed":
                action = "masked"
            logger.info("Policy: Content masked")

        if action == "allowed":
            logger.info("Policy: Content allowed without modification")

        return {
            "action": action,
            "content": modified_content,
        }
