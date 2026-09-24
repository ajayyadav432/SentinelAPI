from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class BflaScanner:
    """OWASP API5:2023 - Broken Function Level Authorization (BFLA) Scanner."""

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        path_lower = endpoint.path.lower()

        # Check if the endpoint appears privileged / administrative
        is_admin_endpoint = (
            endpoint.category == "administration"
            or any(kw in path_lower for kw in ["admin", "root", "manage", "role", "internal", "config", "system", "dashboard/users", "export"])
            or (endpoint.method in ["DELETE", "PUT"] and any(kw in path_lower for kw in ["user", "account", "database", "setting"]))
        )

        if not is_admin_endpoint:
            return findings

        clean_path = endpoint.path
        if "{" in clean_path:
            clean_path = clean_path.replace("{id}", "1").replace("{userId}", "1").replace("{user_id}", "1")

        # 1. Attempt privileged action with standard low-privileged user (User B)
        res_low_priv = await self.client.request(
            method=endpoint.method,
            path=clean_path,
            token=self.session.user_b.token
        )

        if res_low_priv.status_code in [200, 201, 204]:
            evidence = (
                f"Standard non-admin user (role='user') invoked privileged endpoint {endpoint.method} {clean_path} "
                f"and received status HTTP {res_low_priv.status_code} ({len(res_low_priv.body)} bytes). Expected HTTP 403 Forbidden."
            )
            explanation = await self.ai.explain_vulnerability({
                "vuln_type": "OWASP API5:2023 - Broken Function Level Authorization (BFLA)",
                "endpoint": clean_path,
                "method": endpoint.method,
                "evidence": evidence
            })

            findings.append(Finding(
                vuln_type="OWASP API5:2023 - Broken Function Level Authorization (BFLA)",
                category="BFLA",
                severity="CRITICAL",
                cvss_score=9.1,
                owasp_tag="API5:2023",
                endpoint=clean_path,
                method=endpoint.method,
                evidence=evidence,
                reproduction_curl=res_low_priv.curl_command,
                attacker_token_used=self.session.user_b.token,
                status_code_observed=res_low_priv.status_code,
                response_snippet=res_low_priv.body[:300],
                plain_english_summary=explanation.get("plain_english_summary", ""),
                business_impact=explanation.get("business_impact", ""),
                remediation_steps=explanation.get("remediation_steps", []),
                code_fix_example=explanation.get("code_fix_example", "")
            ))

        # 2. Check HTTP Method Tampering bypass (e.g. override header)
        if endpoint.method in ["POST", "PUT", "DELETE"]:
            res_tamper = await self.client.request(
                method="GET",
                path=clean_path,
                headers={"X-HTTP-Method-Override": endpoint.method},
                token=self.session.user_b.token
            )
            if res_tamper.status_code in [200, 201, 204] and res_tamper.status_code != res_low_priv.status_code:
                findings.append(Finding(
                    vuln_type="OWASP API5:2023 - HTTP Method Override Authorization Bypass",
                    category="BFLA",
                    severity="HIGH",
                    cvss_score=8.1,
                    owasp_tag="API5:2023",
                    endpoint=clean_path,
                    method="GET (with X-HTTP-Method-Override)",
                    evidence=f"Endpoint allowed state change via HTTP Method Override header 'X-HTTP-Method-Override: {endpoint.method}' bypassing normal method authorization controls.",
                    reproduction_curl=res_tamper.curl_command,
                    status_code_observed=res_tamper.status_code,
                    response_snippet=res_tamper.body[:250],
                    plain_english_summary="Administrative action can be executed via method-override headers without proper RBAC checks.",
                    business_impact="Bypasses standard API gateway WAF rules that only inspect standard HTTP verbs."
                ))

        return findings
