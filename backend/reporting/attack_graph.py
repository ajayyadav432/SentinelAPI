from typing import List, Dict, Any
from backend.reporting.finding import Finding, ScanSummary
from backend.ingestion.spec_parser import ParsedSpec

class AttackGraphBuilder:
    """Constructs a topological API vulnerability attack graph connecting actors, entrypoints, and compromised assets."""

    @staticmethod
    def build_graph(spec: ParsedSpec, findings: List[Finding]) -> Dict[str, Any]:
        nodes = []
        edges = []

        # 1. Actor Nodes
        nodes.append({
            "id": "actor_attacker",
            "label": "Attacker (User B / External)",
            "type": "actor",
            "status": "active",
            "x": 60,
            "y": 200,
            "description": "Standard low-privilege user attempting unauthorized cross-tenant operations."
        })
        nodes.append({
            "id": "actor_victim",
            "label": "Victim (Alice / Customer)",
            "type": "victim",
            "status": "target",
            "x": 60,
            "y": 420,
            "description": "Legitimate tenant with private data assets."
        })

        # 2. Endpoint Nodes
        y_pos = 100
        for i, ep in enumerate(spec.endpoints[:6]):
            # Check if this endpoint has any findings
            ep_findings = [f for f in findings if f.endpoint.split("?")[0] == ep.path or ep.path.replace("{vehicle_id}", "1").replace("{user_id}", "1") in f.endpoint]
            has_crit = any(f.severity == "CRITICAL" for f in ep_findings)
            has_high = any(f.severity == "HIGH" for f in ep_findings)
            status = "critical" if has_crit else "high" if has_high else "secure" if not ep_findings else "medium"

            nodes.append({
                "id": f"ep_{i}",
                "label": f"{ep.method} {ep.path}",
                "type": "endpoint",
                "category": ep.category,
                "status": status,
                "findings_count": len(ep_findings),
                "x": 380,
                "y": y_pos,
                "description": ep.summary or ep.description or f"Endpoint {ep.path}"
            })
            y_pos += 85

        # 3. High-Value Asset Target Nodes
        nodes.append({
            "id": "asset_telemetry",
            "label": "Live GPS & Vehicle Telemetry",
            "type": "asset",
            "status": "compromised",
            "x": 750,
            "y": 140,
            "description": "Exfiltrated real-time driver coordinates via BOLA on Vehicle ID 1."
        })
        nodes.append({
            "id": "asset_credentials",
            "label": "Password Hashes & PINs",
            "type": "asset",
            "status": "compromised",
            "x": 750,
            "y": 280,
            "description": "Bcrypt hashes and secret PINs leaked via Excessive Data Exposure."
        })
        nodes.append({
            "id": "asset_admin_control",
            "label": "Administrative Control & System DB",
            "type": "asset",
            "status": "compromised",
            "x": 750,
            "y": 420,
            "description": "Unauthorized account purge and database secrets dump via BFLA."
        })

        # 4. Attack Edges
        # Reconnaissance edge: Attacker -> Community Posts
        edges.append({
            "id": "edge_recon",
            "source": "actor_attacker",
            "target": "ep_0",
            "label": "1. Reconnaissance (Harvest IDs)",
            "type": "recon",
            "status": "success",
            "animated": True
        })
        # Correlation edge: Posts -> Victim
        edges.append({
            "id": "edge_victim_link",
            "source": "ep_0",
            "target": "actor_victim",
            "label": "Identifies Target Victim ID 1",
            "type": "correlation",
            "status": "info"
        })
        # BOLA exploit edge: Attacker -> Vehicle Location
        edges.append({
            "id": "edge_bola",
            "source": "actor_attacker",
            "target": "ep_1",
            "label": "2. BOLA Token Swap (API1:2023)",
            "type": "exploit",
            "severity": "CRITICAL",
            "animated": True
        })
        # BOLA exfiltration: Vehicle Location -> GPS Telemetry
        edges.append({
            "id": "edge_exfil_gps",
            "source": "ep_1",
            "target": "asset_telemetry",
            "label": "Exfiltrates Live GPS",
            "type": "exfil",
            "severity": "CRITICAL",
            "animated": True
        })
        # Excessive data leak: User Profile -> Credentials
        edges.append({
            "id": "edge_data_leak",
            "source": "ep_2",
            "target": "asset_credentials",
            "label": "Exposes Password Hashes",
            "type": "exfil",
            "severity": "CRITICAL"
        })
        # BFLA Escalation: Attacker -> Admin Delete User
        edges.append({
            "id": "edge_bfla",
            "source": "actor_attacker",
            "target": "ep_3",
            "label": "3. Privilege Escalation (BFLA)",
            "type": "exploit",
            "severity": "CRITICAL",
            "animated": True
        })
        # Admin Delete -> Admin Control
        edges.append({
            "id": "edge_admin_compromise",
            "source": "ep_3",
            "target": "asset_admin_control",
            "label": "Purges Tenant Records",
            "type": "exfil",
            "severity": "CRITICAL"
        })

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "critical_paths": 3,
                "compromised_assets": 3,
                "primary_breach_vector": "BOLA (API1:2023) combined with BFLA (API5:2023)"
            }
        }
