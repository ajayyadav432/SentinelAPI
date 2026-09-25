from typing import List, Dict, Any, Set
from backend.reporting.finding import Finding, ScanSummary
from backend.ingestion.spec_parser import ParsedSpec

class AttackGraphBuilder:
    """Constructs a topological API vulnerability attack graph connecting actors, entrypoints, and compromised assets."""

    # Maps OWASP category → human-readable asset label derived from finding evidence
    _CATEGORY_ASSET_LABELS: Dict[str, str] = {
        "BOLA": "Cross-Tenant Object Data",
        "BFLA": "Administrative Functions & System Config",
        "DATA_EXPOSURE": "Sensitive Fields (PII / Credentials)",
        "SCHEMA_DRIFT": "Undocumented Internal Schema Fields",
        "RATE_LIMIT": "Rate-Limited Resources (Brute-Force Target)",
        "MISCONFIG": "Security Boundary (CORS / Headers)",
    }

    @staticmethod
    def build_graph(spec: ParsedSpec, findings: List[Finding]) -> Dict[str, Any]:
        nodes = []
        edges = []

        # 1. Actor Nodes
        nodes.append({
            "id": "actor_attacker",
            "label": "Attacker (External / Low-Privilege)",
            "type": "actor",
            "status": "active",
            "x": 60,
            "y": 180,
            "description": "Authenticated but unauthorized user attempting cross-tenant operations."
        })
        nodes.append({
            "id": "actor_victim",
            "label": "Victim (Legitimate User)",
            "type": "victim",
            "status": "target",
            "x": 60,
            "y": 370,
            "description": "Legitimate tenant whose private data is targeted."
        })

        # 2. Endpoint Nodes — dynamically built from spec
        y_pos = 75
        # Map endpoint path -> node id for edge wiring
        ep_node_map: Dict[str, str] = {}
        for i, ep in enumerate(spec.endpoints[:8]):
            node_id = f"ep_{i}"
            ep_node_map[ep.path] = node_id

            # Determine status from real findings for this endpoint
            ep_findings = [
                f for f in findings
                if ep.path in f.endpoint or f.endpoint.split("?")[0] == ep.path
            ]
            has_crit = any(f.severity == "CRITICAL" for f in ep_findings)
            has_high = any(f.severity == "HIGH" for f in ep_findings)
            status = (
                "critical" if has_crit
                else "high" if has_high
                else "medium" if ep_findings
                else "secure"
            )

            nodes.append({
                "id": node_id,
                "label": f"{ep.method} {ep.path}",
                "type": "endpoint",
                "category": ep.category,
                "status": status,
                "findings_count": len(ep_findings),
                "x": 380,
                "y": y_pos,
                "description": ep.summary or ep.description or f"Endpoint: {ep.path}"
            })
            y_pos += 75

        # 3. Asset Nodes — dynamically derived from actual findings categories
        seen_categories: Set[str] = set()
        asset_nodes: Dict[str, str] = {}  # category -> node_id
        x_asset = 750
        y_asset = 130
        for f in findings:
            cat = f.category
            if cat not in seen_categories:
                seen_categories.add(cat)
                asset_id = f"asset_{cat.lower()}"
                label = AttackGraphBuilder._CATEGORY_ASSET_LABELS.get(
                    cat, f"{cat.replace('_', ' ').title()} Resource"
                )
                # Build a concise description from the first finding of this category
                desc = f.plain_english_summary[:120] if f.plain_english_summary else f"Compromised via {f.owasp_tag}"
                nodes.append({
                    "id": asset_id,
                    "label": label,
                    "type": "asset",
                    "status": "compromised" if f.severity in ["CRITICAL", "HIGH"] else "exposed",
                    "owasp_tag": f.owasp_tag,
                    "x": x_asset,
                    "y": y_asset,
                    "description": desc
                })
                asset_nodes[cat] = asset_id
                y_asset += 90

        # 4. Edges — dynamically wired from actual findings
        # Recon edge: Attacker -> first public (no-path-id) GET endpoint
        public_eps = [ep for ep in spec.endpoints if ep.method == "GET" and not ep.has_path_id]
        if public_eps:
            recon_target = ep_node_map.get(public_eps[0].path, "ep_0")
            edges.append({
                "id": "edge_recon",
                "source": "actor_attacker",
                "target": recon_target,
                "label": "1. Reconnaissance (Enumerate IDs)",
                "type": "recon",
                "status": "success",
                "animated": True
            })
            edges.append({
                "id": "edge_victim_link",
                "source": recon_target,
                "target": "actor_victim",
                "label": "Identifies Victim Object IDs",
                "type": "correlation",
                "status": "info"
            })

        # Exploit edges: one per unique finding endpoint
        seen_exploit_eps: Set[str] = set()
        edge_counter = 1
        for f in findings:
            # Find the matching spec endpoint node
            matched_node = None
            for ep_path, node_id in ep_node_map.items():
                if ep_path in f.endpoint or f.endpoint.startswith(ep_path.split("{")[0]):
                    matched_node = node_id
                    break

            if matched_node and matched_node not in seen_exploit_eps:
                seen_exploit_eps.add(matched_node)
                owasp_label = f.owasp_tag or f.category
                edges.append({
                    "id": f"edge_exploit_{edge_counter}",
                    "source": "actor_attacker",
                    "target": matched_node,
                    "label": f"{edge_counter + 1}. {f.category} ({owasp_label})",
                    "type": "exploit",
                    "severity": f.severity,
                    "animated": f.severity == "CRITICAL"
                })
                edge_counter += 1

            # Exfil edge: endpoint -> asset
            if matched_node and f.category in asset_nodes:
                exfil_id = f"edge_exfil_{f.id}"
                edges.append({
                    "id": exfil_id,
                    "source": matched_node,
                    "target": asset_nodes[f.category],
                    "label": f"Exfiltrates via {f.method} ({f.severity})",
                    "type": "exfil",
                    "severity": f.severity,
                    "animated": f.severity == "CRITICAL"
                })

        # Compute summary stats from real data
        critical_paths = sum(1 for f in findings if f.severity == "CRITICAL")
        compromised_assets = len(seen_categories)
        categories = list(seen_categories)
        primary_vector = (
            f"{categories[0]} ({findings[0].owasp_tag})" if findings
            else "No vulnerabilities detected"
        )

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "critical_paths": max(critical_paths, 1) if findings else 0,
                "compromised_assets": compromised_assets,
                "primary_breach_vector": primary_vector
            }
        }
