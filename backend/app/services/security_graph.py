"""
Security Graph — lightweight in-memory relational intelligence engine.
Builds an entity graph (IPs, Users, Resources) from log content and detects lateral movement.
"""

import re
from collections import defaultdict
from app.core.logging_config import logger
from app.utils.patterns import IP_ADDRESS_PATTERN


class SecurityGraph:
    """
    Builds a graph of entities from analyzed content and detects:
    - Lateral movement (IP → multiple resources)
    - Suspicious IP chains (low-risk IP connecting to high-value assets)
    - Relationship clusters (same user from multiple IPs)
    """

    # Patterns to extract usernames and resources from logs
    USER_PATTERN = re.compile(
        r'(?:user(?:name)?|usr|uid)\s*[=:]\s*["\']?([a-zA-Z0-9_@.\-]{2,64})["\']?',
        re.IGNORECASE,
    )
    RESOURCE_PATTERN = re.compile(
        r'(?:uri|url|path|endpoint|resource|dest(?:_ip)?)\s*[=:]\s*["\']?(/[^\s"\']{2,})["\']?',
        re.IGNORECASE,
    )
    SENSITIVE_RESOURCES = re.compile(
        r"(?:/admin|/root|/config|/backup|/passwd|/shadow|/etc/|"
        r"/api/internal|/manage|/console|/dashboard|/secret)",
        re.IGNORECASE,
    )

    def build_and_analyze(self, content: str) -> dict:
        """
        Parse content and build an entity-relationship graph.
        Returns graph data and lateral movement detections.
        """
        logger.info("Building security entity graph")
        lines = content.split("\n")

        # Entity collections
        ip_to_users: dict[str, set] = defaultdict(set)
        ip_to_resources: dict[str, set] = defaultdict(set)
        user_to_ips: dict[str, set] = defaultdict(set)
        user_to_resources: dict[str, set] = defaultdict(set)
        sensitive_accesses: list[dict] = []

        nodes = {}  # node_id → {type, id, properties}
        edges = []  # {from, to, relation, line}

        for line_num, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            ips = list(set(IP_ADDRESS_PATTERN.findall(line)))
            users_found = [m.group(1) for m in self.USER_PATTERN.finditer(line)]
            resources_found = [m.group(1) for m in self.RESOURCE_PATTERN.finditer(line)]

            for ip in ips:
                if ip in ("127.0.0.1", "0.0.0.0"):
                    continue
                node_id = f"ip:{ip}"
                if node_id not in nodes:
                    nodes[node_id] = {"type": "ip", "id": ip, "risk": "low"}

                for user in users_found:
                    if user.upper() == "N/A":
                        continue
                    uid = f"user:{user}"
                    if uid not in nodes:
                        nodes[uid] = {"type": "user", "id": user, "risk": "low"}
                    ip_to_users[ip].add(user)
                    user_to_ips[user].add(ip)
                    edges.append({"from": node_id, "to": uid, "relation": "authenticated_as", "line": line_num})

                for resource in resources_found:
                    rid = f"resource:{resource}"
                    if rid not in nodes:
                        is_sensitive = bool(self.SENSITIVE_RESOURCES.search(resource))
                        nodes[rid] = {"type": "resource", "id": resource, "sensitive": is_sensitive, "risk": "critical" if is_sensitive else "low"}
                    ip_to_resources[ip].add(resource)
                    edges.append({"from": node_id, "to": f"resource:{resource}", "relation": "accessed", "line": line_num})

                    if self.SENSITIVE_RESOURCES.search(resource):
                        sensitive_accesses.append({
                            "ip": ip,
                            "resource": resource,
                            "line": line_num,
                        })

        # ── Lateral Movement Detection ────────────────────────────────────────
        lateral_movement = []

        # Pattern 1: Single IP accessing many different sensitive resources
        for ip, resources in ip_to_resources.items():
            sensitive = [r for r in resources if self.SENSITIVE_RESOURCES.search(r)]
            if len(sensitive) >= 2:
                lateral_movement.append({
                    "type": "IP Multi-Target Access",
                    "description": f"IP {ip} accessed {len(sensitive)} sensitive resources",
                    "entities": [ip] + sensitive[:4],
                    "severity": "critical",
                })

        # Pattern 2: Single user authenticated from multiple IPs (account sharing / takeover)
        for user, ips in user_to_ips.items():
            if len(ips) >= 2:
                lateral_movement.append({
                    "type": "Multi-IP User Session",
                    "description": f"User '{user}' authenticated from {len(ips)} different IPs — possible account takeover",
                    "entities": [user] + list(ips)[:4],
                    "severity": "high",
                })

        # Pattern 3: Low-volume IP suddenly accessing admin resource
        for sa in sensitive_accesses:
            ip = sa["ip"]
            total_hits = len(ip_to_resources.get(ip, []))
            if total_hits <= 2:
                lateral_movement.append({
                    "type": "Low-Profile Sensitive Access",
                    "description": f"IP {ip} with minimal activity directly accessed sensitive resource: {sa['resource']}",
                    "entities": [sa["ip"], sa["resource"]],
                    "severity": "high",
                })

        logger.info(
            f"Graph built: {len(nodes)} nodes, {len(edges)} edges, "
            f"{len(lateral_movement)} lateral movement paths"
        )

        return {
            "graph_nodes": len(nodes),
            "graph_edges": len(edges),
            "node_types": {
                "ips": sum(1 for n in nodes.values() if n["type"] == "ip"),
                "users": sum(1 for n in nodes.values() if n["type"] == "user"),
                "resources": sum(1 for n in nodes.values() if n["type"] == "resource"),
            },
            "sensitive_accesses": sensitive_accesses[:10],
            "lateral_movement_paths": lateral_movement[:10],
        }
