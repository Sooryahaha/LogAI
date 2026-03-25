"""
MCP Agentic Gateway — Model Context Protocol security gateway.
Every tool call is authorized against an Agent ID with scoped permissions.
Destructive actions are blocked for unauthorized agents.
"""

from enum import Enum
from datetime import datetime, timezone
from app.core.logging_config import logger


class AgentRole(str, Enum):
    READER = "READER"
    ANALYST = "ANALYST"
    RESPONDER = "RESPONDER"
    ADMIN = "ADMIN"


# Tool permission matrix
TOOL_PERMISSIONS: dict[str, list[AgentRole]] = {
    # Read-only
    "analyze": [AgentRole.READER, AgentRole.ANALYST, AgentRole.RESPONDER, AgentRole.ADMIN],
    "graph": [AgentRole.READER, AgentRole.ANALYST, AgentRole.RESPONDER, AgentRole.ADMIN],
    "insights": [AgentRole.READER, AgentRole.ANALYST, AgentRole.RESPONDER, AgentRole.ADMIN],
    # Analyst+
    "twin_simulate": [AgentRole.ANALYST, AgentRole.RESPONDER, AgentRole.ADMIN],
    "risk_score": [AgentRole.ANALYST, AgentRole.RESPONDER, AgentRole.ADMIN],
    # Responder+  (destructive / active response)
    "mask_content": [AgentRole.RESPONDER, AgentRole.ADMIN],
    "block_request": [AgentRole.RESPONDER, AgentRole.ADMIN],
    "honeypot_deploy": [AgentRole.RESPONDER, AgentRole.ADMIN],
    # Admin only
    "policy_override": [AgentRole.ADMIN],
    "redact_logs": [AgentRole.ADMIN],
}


class MCPPermissionDenied(Exception):
    pass


class MCPGateway:
    """
    Security gateway that enforces identity-based scoping on every tool call.
    Returns an audit log of all authorization decisions.
    """

    def __init__(self, agent_id: str = "ANALYST"):
        # Normalize agent_id to a valid role, default ANALYST
        try:
            self.agent_role = AgentRole(agent_id.upper())
        except ValueError:
            self.agent_role = AgentRole.ANALYST
        self.audit_log: list[dict] = []

    def authorize(self, tool_name: str) -> bool:
        """
        Check if the current agent role is authorized to call tool_name.
        Raises MCPPermissionDenied if not authorized.
        Records every decision in the audit log.
        """
        allowed_roles = TOOL_PERMISSIONS.get(tool_name, [AgentRole.ADMIN])
        authorized = self.agent_role in allowed_roles

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_role.value,
            "tool": tool_name,
            "authorized": authorized,
        }
        self.audit_log.append(entry)

        if authorized:
            logger.info(f"MCP: AUTHORIZED {self.agent_role.value} → {tool_name}")
        else:
            logger.warning(f"MCP: DENIED {self.agent_role.value} → {tool_name}")
            raise MCPPermissionDenied(
                f"Agent '{self.agent_role.value}' is not authorized to use tool '{tool_name}'. "
                f"Required: one of {[r.value for r in allowed_roles]}"
            )

        return True

    def get_audit_summary(self) -> dict:
        return {
            "agent_id": self.agent_role.value,
            "total_calls": len(self.audit_log),
            "authorized": sum(1 for e in self.audit_log if e["authorized"]),
            "denied": sum(1 for e in self.audit_log if not e["authorized"]),
            "log": self.audit_log,
        }
