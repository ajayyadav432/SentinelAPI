import re
import json
from typing import List, Optional, Dict, Any
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class DataExposureScanner:
    """OWASP API3:2023 - Broken Object Property Level Authorization & Excessive Data Exposure."""

    SENSITIVE_KEY_PATTERNS = [
        (re.compile(r"password|passwd|pwd|pass_hash", re.I), "Password / Credential Field", "CRITICAL", 8.9),
        (re.compile(r"private_key|secret_key|client_secret|aws_key", re.I), "Secret Cryptographic Key", "CRITICAL", 9.2),
        (re.compile(r"access_token|refresh_token|jwt_token|bearer", re.I), "Auth / Session Token", "HIGH", 7.8),
        (re.compile(r"ssn|social_security|national_id", re.I), "Government / National ID (SSN)", "HIGH", 8.2),
        (re.compile(r"credit_card|cvv|card_number|pan", re.I), "Payment Card Data", "CRITICAL", 9.0),
        (re.compile(r"salary|bank_account|balance", re.I), "Sensitive Financial Data", "MEDIUM", 6.5),
        (re.compile(r"traceback|exception|sql_error|stack_trace", re.I), "Internal Debug Stack Trace", "MEDIUM", 5.5)
    ]

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    def _find_sensitive_keys(self, obj: Any, path: str = "") -> List[Dict[str, Any]]:
        matches = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                curr_path = f"{path}.{k}" if path else k
                for pattern, name, sev, cvss in self.SENSITIVE_KEY_PATTERNS:
                    if pattern.search(k):
                        matches.append({
                            "key": curr_path,
                            "name": name,
                            "severity": sev,
                            "cvss": cvss,
                            "sample_val": str(v)[:60]
                        })
                matches.extend(self._find_sensitive_keys(v, curr_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):
                matches.extend(self._find_sensitive_keys(item, f"{path}[{i}]"))
        return matches

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        if endpoint.method not in ["GET", "POST"]:
            return findings

        clean_path = endpoint.path
        if "{" in clean_path:
            clean_path = clean_path.replace("{id}", "1").replace("{userId}", "1")

        # Execute GET request with authenticated user
        res = await self.client.request(
            method=endpoint.method,
            path=clean_path,
            token=self.session.user_a.token
        )

        if res.status_code == 200 and res.json_data:
            sensitive_hits = self._find_sensitive_keys(res.json_data)
            if sensitive_hits:
                top_hit = max(sensitive_hits, key=lambda x: x["cvss"])
                keys_found = ", ".join([f"'{h['key']}' ({h['name']})" for h in sensitive_hits[:4]])
                
                evidence = (
                    f"Endpoint {endpoint.method} {clean_path} exposed sensitive internal properties in JSON response: {keys_found}. "
                    f"Sample leak: {top_hit['key']} = '{top_hit['sample_val']}'"
                )

                explanation = await self.ai.explain_vulnerability({
                    "vuln_type": "OWASP API3:2023 - Excessive Data Exposure",
                    "endpoint": clean_path,
                    "method": endpoint.method,
                    "evidence": evidence
                })

                findings.append(Finding(
                    vuln_type="OWASP API3:2023 - Broken Object Property Level Authorization (Data Exposure)",
                    category="DATA_EXPOSURE",
                    severity=top_hit["severity"],
                    cvss_score=top_hit["cvss"],
                    owasp_tag="API3:2023",
                    endpoint=clean_path,
                    method=endpoint.method,
                    evidence=evidence,
                    reproduction_curl=res.curl_command,
                    status_code_observed=res.status_code,
                    response_snippet=res.body[:300],
                    plain_english_summary=explanation.get("plain_english_summary", ""),
                    business_impact=explanation.get("business_impact", ""),
                    remediation_steps=explanation.get("remediation_steps", []),
                    code_fix_example=explanation.get("code_fix_example", "")
                ))

        return findings
