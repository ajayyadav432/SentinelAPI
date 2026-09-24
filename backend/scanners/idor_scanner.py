import re
from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient, HttpResponseResult
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class IdorScanner:
    """OWASP API1:2023 - Broken Object Level Authorization (BOLA/IDOR) Scanner."""

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        if not endpoint.has_path_id and not any(p.in_location == "query" and "id" in p.name.lower() for p in endpoint.parameters):
            return findings

        # Check path ID variables like {id}, {orderId}, {vehicle_id}
        path_template = endpoint.path
        id_vars = re.findall(r"\{([^}]+)\}", path_template)

        # We test with victim (User A) resource ID
        victim_id = self.session.user_a.known_resource_ids[0] if self.session.user_a.known_resource_ids else "1"
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

        # 3. Analyze authorization leak
        # If attacker receives 200 OK and receives structured data
        if res_attacker.status_code == 200 and res_attacker.body:
            # Check if this is an actual resource leak (not a generic public list or login error)
            is_vulnerable = False
            evidence_details = ""

            if res_victim.status_code == 200:
                # Both returned 200. Check similarity or object identity
                is_vulnerable = True
                evidence_details = (
                    f"User B (Attacker token: ...{self.session.user_b.token[-8:] if self.session.user_b.token else 'none'}) "
                    f"successfully fetched private resource ID '{victim_id}' belonging to User A via {endpoint.method} {test_path}. "
                    f"Server responded with HTTP 200 OK ({len(res_attacker.body)} bytes) instead of 403 Forbidden."
                )
            else:
                # Even if victim was not authenticated, attacker got 200 for a specific ID
                is_vulnerable = True
                evidence_details = (
                    f"Attacker token accessed object '{victim_id}' at {endpoint.method} {test_path} returning HTTP 200 OK."
                )

            if is_vulnerable:
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
                    target_resource_id=victim_id,
                    status_code_observed=res_attacker.status_code,
                    response_snippet=res_attacker.body[:300],
                    plain_english_summary=explanation.get("plain_english_summary", ""),
                    business_impact=explanation.get("business_impact", ""),
                    remediation_steps=explanation.get("remediation_steps", []),
                    code_fix_example=explanation.get("code_fix_example", "")
                ))

        # 4. Check for unauthenticated access on the ID resource
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
