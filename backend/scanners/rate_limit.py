import asyncio
from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class RateLimitScanner:
    """OWASP API4:2023 - Unrestricted Resource Consumption (Missing / Weak Rate Limiting)."""

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        path_lower = endpoint.path.lower()

        # Prioritize authentication, OTP, reset-password, and resource creation
        is_sensitive_flow = (
            endpoint.category in ["authentication", "financial"]
            or any(kw in path_lower for kw in ["login", "signin", "otp", "verify", "password", "reset", "order", "token", "coupon", "checkout"])
        )

        if not is_sensitive_flow:
            return findings

        clean_path = endpoint.path
        if "{" in clean_path:
            clean_path = clean_path.replace("{id}", "1").replace("{userId}", "1")

        # Execute concurrent burst of 20 rapid requests
        burst_size = 20
        tasks = []
        for _ in range(burst_size):
            tasks.append(self.client.request(
                method=endpoint.method,
                path=clean_path,
                token=self.session.user_b.token
            ))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [r for r in results if not isinstance(r, Exception) and r.status_code != 0]
        if not valid_results:
            return findings

        # Check for 429 response or rate limit headers
        has_429 = any(r.status_code == 429 for r in valid_results)
        sample_resp = valid_results[0]
        has_rate_headers = any(h in sample_resp.headers for h in ["x-ratelimit-limit", "ratelimit-limit", "retry-after"])

        if not has_429 and not has_rate_headers and len(valid_results) >= 15:
            success_count = sum(1 for r in valid_results if r.status_code in [200, 201, 400, 401])
            evidence = (
                f"Sent {burst_size} concurrent requests to {endpoint.method} {clean_path}. "
                f"Server processed {success_count}/{burst_size} requests without throttling or returning HTTP 429 Too Many Requests. "
                f"Missing standard rate-limit headers (Retry-After, X-RateLimit-*)."
            )

            explanation = await self.ai.explain_vulnerability({
                "vuln_type": "OWASP API4:2023 - Unrestricted Resource Consumption (Rate Limiting)",
                "endpoint": clean_path,
                "method": endpoint.method,
                "evidence": evidence
            })

            findings.append(Finding(
                vuln_type="OWASP API4:2023 - Unrestricted Resource Consumption (Missing Rate Limiting)",
                category="RATE_LIMIT",
                severity="HIGH",
                cvss_score=7.6,
                owasp_tag="API4:2023",
                endpoint=clean_path,
                method=endpoint.method,
                evidence=evidence,
                reproduction_curl=sample_resp.curl_command,
                status_code_observed=sample_resp.status_code,
                response_snippet=f"Accepted {success_count} concurrent requests within 500ms.",
                plain_english_summary=explanation.get("plain_english_summary", ""),
                business_impact=explanation.get("business_impact", ""),
                remediation_steps=explanation.get("remediation_steps", []),
                code_fix_example=explanation.get("code_fix_example", "")
            ))

        return findings
