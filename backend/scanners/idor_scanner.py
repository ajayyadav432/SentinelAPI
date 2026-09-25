import re
import difflib
from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient, HttpResponseResult
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class IdorScanner:
    """OWASP API1:2023 - Broken Object Level Authorization (BOLA/IDOR) Scanner."""

    # Minimum body similarity ratio to confirm same resource was returned (not a generic error body)
    _BODY_SIMILARITY_THRESHOLD = 0.65

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    def _is_same_resource(self, body_a: str, body_b: str) -> bool:
        """Returns True if User B received the same data as User A (confirmed leak, not a generic 200)."""
        if not body_a or not body_b:
            return bool(body_b)
        # Avoid false positives from identical empty/error responses
        if len(body_b.strip()) < 20:
            return False
        ratio = difflib.SequenceMatcher(None, body_a[:500], body_b[:500]).ratio()
        return ratio >= self._BODY_SIMILARITY_THRESHOLD

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        if not endpoint.has_path_id and not any(p.in_location == "query" and "id" in p.name.lower() for p in endpoint.parameters):
            return findings

        # Check path ID variables like {id}, {orderId}, {vehicle_id}
        path_template = endpoint.path
        id_vars = re.findall(r"\{([^}]+)\}", path_template)

        # Use the actual victim ID from session; fallback to "1"
        base_victim_id = (
            self.session.user_a.known_resource_ids[0]
            if self.session.user_a.known_resource_ids
            else "1"
        )

        # Generate smart candidate IDs (sequential, negatives, UUIDs, etc.)
        candidate_ids = await self.ai.generate_smart_idor_ids(
            param_name=id_vars[0] if id_vars else "id",
            sample_id=base_victim_id
        )
        # Always test the real victim ID first
        candidate_ids = [base_victim_id] + [c for c in candidate_ids if c != base_victim_id]

        for victim_id in candidate_ids[:5]:  # Cap at 5 candidates per endpoint to avoid hammering
            test_path = path_template
            for var in id_vars:
                test_path = test_path.replace(f"{{{var}}}", str(victim_id))

            # Query param IDs
            query_params = {}
            for p in endpoint.parameters:
                if p.in_location == "query" and ("id" in p.name.lower() or "user" in p.name.lower()):
                    query_params[p.name] = victim_id

            # 1. Baseline Request with Victim (User A)
            res_victim = await self.client.request(
                method=endpoint.method,
                path=test_path,
                params=query_params if query_params else None,
                token=self.session.user_a.token
            )

            # 2. Attack Request with Attacker (User B) accessing User A's resource
            res_attacker = await self.client.request(
                method=endpoint.method,
                path=test_path,
                params=query_params if query_params else None,
                token=self.session.user_b.token
            )

            # 3. Body-Diffing False-Positive Elimination
            # Only flag BOLA if User B received the SAME resource data as User A (not just any 200)
            if res_attacker.status_code == 200 and res_attacker.body:
                victim_ok = res_victim.status_code == 200

                # Core confirmation: bodies must be meaningfully similar (same object returned)
                is_same_resource = self._is_same_resource(
                    res_victim.body if victim_ok else "",
                    res_attacker.body
                )

                if is_same_resource:
                    similarity_pct = round(
                        difflib.SequenceMatcher(None, res_victim.body[:500], res_attacker.body[:500]).ratio() * 100, 1
                    ) if victim_ok else "N/A"

                    evidence_details = (
                        f"User B (Attacker token: ...{self.session.user_b.token[-8:] if self.session.user_b.token else 'none'}) "
                        f"successfully fetched private resource ID '{victim_id}' belonging to User A via {endpoint.method} {test_path}. "
                        f"Server responded HTTP 200 OK ({len(res_attacker.body)} bytes) instead of 403 Forbidden. "
                        f"Response body similarity with legitimate owner response: {similarity_pct}%."
                    )

                    explanation = await self.ai.explain_vulnerability({
                        "vuln_type": "OWASP API1:2023 - Broken Object Level Authorization (BOLA/IDOR)",
                        "endpoint": test_path,
                        "method": endpoint.method,
                        "evidence": evidence_details
                    })

                    findings.append(Finding(
                        vuln_type="OWASP API1:2023 - Broken Object Level Authorization (BOLA / IDOR)",
                        category="BOLA",
                        severity="CRITICAL",
                        cvss_score=8.8,
                        owasp_tag="API1:2023",
                        endpoint=test_path,
                        method=endpoint.method,
                        evidence=evidence_details,
                        reproduction_curl=res_attacker.curl_command,
                        attacker_token_used=self.session.user_b.token,
                        target_resource_id=str(victim_id),
                        status_code_observed=res_attacker.status_code,
                        response_snippet=res_attacker.body[:300],
                        plain_english_summary=explanation.get("plain_english_summary", ""),
                        business_impact=explanation.get("business_impact", ""),
                        remediation_steps=explanation.get("remediation_steps", []),
                        code_fix_example=explanation.get("code_fix_example", "")
                    ))
                    # Found a confirmed BOLA on this endpoint — no need to try more IDs
                    break

            # 4. Check for unauthenticated access on the ID resource (only on base victim ID)
            if victim_id == base_victim_id:
                res_anon = await self.client.request(
                    method=endpoint.method,
                    path=test_path,
                    params=query_params if query_params else None,
                    token=None
                )
                if res_anon.status_code == 200 and endpoint.requires_auth:
                    findings.append(Finding(
                        vuln_type="OWASP API2:2023 - Broken Authentication (Unauthenticated ID Access)",
                        category="BOLA",
                        severity="HIGH",
                        cvss_score=7.5,
                        owasp_tag="API2:2023",
                        endpoint=test_path,
                        method=endpoint.method,
                        evidence=f"Anonymous unauthenticated request to {endpoint.method} {test_path} succeeded with HTTP 200 OK without requiring Authorization headers.",
                        reproduction_curl=res_anon.curl_command,
                        status_code_observed=200,
                        response_snippet=res_anon.body[:250],
                        plain_english_summary="Resource endpoint is completely unauthenticated and accessible by any public user on the internet.",
                        business_impact="Unrestricted data exfiltration without even creating an account.",
                        remediation_steps=[
                            "Add authentication middleware to reject requests without a valid Bearer token with HTTP 401 Unauthorized."
                        ]
                    ))

        return findings
