from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class MisconfigScanner:
    """OWASP API8:2023 - Security Misconfiguration Scanner."""

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        clean_path = endpoint.path
        if "{" in clean_path:
            clean_path = clean_path.replace("{id}", "1").replace("{userId}", "1")

        # 1. Test CORS Misconfiguration
        evil_origin = "https://attacker-controlled-site.xyz"
        res_cors = await self.client.request(
            method="OPTIONS" if endpoint.method == "OPTIONS" else "GET",
            path=clean_path,
            headers={
                "Origin": evil_origin,
                "Access-Control-Request-Method": endpoint.method
            },
            token=self.session.user_a.token
        )

        acao = res_cors.headers.get("access-control-allow-origin", "")
        acac = res_cors.headers.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            findings.append(Finding(
                vuln_type="OWASP API8:2023 - Wildcard CORS with Credentials",
                category="MISCONFIG",
                severity="CRITICAL",
                cvss_score=8.5,
                owasp_tag="API8:2023",
                endpoint=clean_path,
                method=endpoint.method,
                evidence=f"API reflects Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true on {clean_path}.",
                reproduction_curl=res_cors.curl_command,
                status_code_observed=res_cors.status_code,
                plain_english_summary="Browser cross-origin requests from arbitrary websites can read authenticated user data.",
                business_impact="Cross-Site Script Inclusion and credential leakage via malicious third-party websites.",
                remediation_steps=[
                    "Never use wildcard '*' when Allow-Credentials is true.",
                    "Whitelist explicit trusted front-end domains in CORS middleware configuration."
                ]
            ))
        elif evil_origin in acao and acac == "true":
            findings.append(Finding(
                vuln_type="OWASP API8:2023 - Arbitrary Origin Reflection in CORS",
                category="MISCONFIG",
                severity="HIGH",
                cvss_score=8.1,
                owasp_tag="API8:2023",
                endpoint=clean_path,
                method=endpoint.method,
                evidence=f"API dynamically reflected arbitrary unverified origin '{acao}' with credentials enabled.",
                reproduction_curl=res_cors.curl_command,
                status_code_observed=res_cors.status_code,
                plain_english_summary="The API blindly trusts any origin header passed by an attacker's browser.",
                business_impact="Account takeover and cross-origin data theft.",
                remediation_steps=[
                    "Validate the incoming Origin against an immutable whitelist array before reflecting headers."
                ]
            ))

        # 2. Check Missing Security Headers & Information Disclosure
        res_sample = await self.client.request(
            method="GET",
            path=clean_path,
            token=self.session.user_a.token
        )

        missing_headers = []
        if "x-content-type-options" not in res_sample.headers:
            missing_headers.append("X-Content-Type-Options: nosniff")
        if "x-frame-options" not in res_sample.headers and "content-security-policy" not in res_sample.headers:
            missing_headers.append("X-Frame-Options / Content-Security-Policy")

        if missing_headers and len(missing_headers) >= 2 and endpoint.path == "/":
            findings.append(Finding(
                vuln_type="OWASP API8:2023 - Missing Essential Defense Headers",
                category="MISCONFIG",
                severity="LOW",
                cvss_score=4.0,
                owasp_tag="API8:2023",
                endpoint=clean_path,
                method=endpoint.method,
                evidence=f"Missing security headers: {', '.join(missing_headers)}",
                reproduction_curl=res_sample.curl_command,
                status_code_observed=res_sample.status_code,
                plain_english_summary="API responses lack defensive browser headers.",
                business_impact="MIME-sniffing and clickjacking vulnerabilities on integrated portals.",
                remediation_steps=[
                    "Add SecurityHeadersMiddleware in backend framework to inject standard defensive headers."
                ]
            ))

        return findings
