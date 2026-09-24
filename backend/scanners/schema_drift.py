import json
from typing import List, Dict, Any, Set
from backend.ingestion.spec_parser import EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class SchemaDriftScanner:
    """Detects Shadow API Drift and Undocumented Property Leaks (Declared vs Actual Payload)."""

    def __init__(self, http_client: AsyncHttpClient, session_mgr: SessionManager, ai_brain: GeminiSecurityBrain):
        self.client = http_client
        self.session = session_mgr
        self.ai = ai_brain

    def _extract_declared_properties(self, responses: Dict[str, Any]) -> Set[str]:
        """Extracts field names explicitly defined in the OpenAPI 200/201 response schema."""
        declared = set()
        for code, resp in responses.items():
            if str(code) in ["200", "201", "default"]:
                content = resp.get("content", {})
                json_schema = content.get("application/json", {}).get("schema", {})
                
                # Check properties if object
                props = json_schema.get("properties", {})
                for p in props.keys():
                    declared.add(p)
                
                # If schema is array of objects
                if json_schema.get("type") == "array":
                    items_props = json_schema.get("items", {}).get("properties", {})
                    for p in items_props.keys():
                        declared.add(p)
        return declared

    def _extract_actual_keys(self, data: Any) -> Set[str]:
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                keys.add(k)
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            for k in data[0].keys():
                keys.add(k)
        return keys

    async def scan_endpoint(self, endpoint: EndpointInfo) -> List[Finding]:
        findings: List[Finding] = []
        if endpoint.method not in ["GET", "POST"]:
            return findings

        declared_fields = self._extract_declared_properties(endpoint.responses)
        if not declared_fields:
            return findings

        clean_path = endpoint.path
        if "{" in clean_path:
            clean_path = clean_path.replace("{id}", "1").replace("{vehicle_id}", "1").replace("{vehicleId}", "1").replace("{userId}", "1")

        res = await self.client.request(
            method=endpoint.method,
            path=clean_path,
            token=self.session.user_a.token
        )

        if res.status_code in [200, 201] and res.json_data:
            actual_keys = self._extract_actual_keys(res.json_data)
            undocumented_keys = actual_keys - declared_fields

            # Filter out generic wrappers like 'data', 'status' if they are standard
            sensitive_shadow_keys = [k for k in undocumented_keys if k not in ["status", "success", "message", "timestamp"]]

            if len(sensitive_shadow_keys) >= 2:
                evidence = (
                    f"Differential Schema Drift on {endpoint.method} {clean_path}: "
                    f"Server returned {len(actual_keys)} properties, but only {len(declared_fields)} were declared in the OpenAPI specification. "
                    f"Undocumented Shadow Fields: {', '.join([f'[{k}]' for k in sorted(sensitive_shadow_keys)[:6]])}."
                )

                explanation = await self.ai.explain_vulnerability({
                    "vuln_type": "OWASP API3:2023 - Differential Schema Drift (Shadow API Leak)",
                    "endpoint": clean_path,
                    "method": endpoint.method,
                    "evidence": evidence
                })

                findings.append(Finding(
                    vuln_type="OWASP API3:2023 - Differential Schema Drift (Shadow Data Leak)",
                    category="DATA_EXPOSURE",
                    severity="HIGH" if any(s in " ".join(sensitive_shadow_keys).lower() for s in ["vin", "gps", "pass", "id", "pin", "hash", "secret"]) else "MEDIUM",
                    cvss_score=7.4,
                    owasp_tag="API3:2023",
                    endpoint=clean_path,
                    method=endpoint.method,
                    evidence=evidence,
                    reproduction_curl=res.curl_command,
                    status_code_observed=res.status_code,
                    response_snippet=f"Declared: {list(declared_fields)} | Actual Keys: {list(actual_keys)}",
                    plain_english_summary=f"The endpoint returns unapproved database properties not documented in the API contract. This indicates raw ORM serialization leaking internal backend fields.",
                    business_impact="Exposes internal schema architecture and undocumented data points to attackers.",
                    remediation_steps=[
                        "Implement strict response DTOs / Pydantic models with explicit field whitelisting.",
                        "Audit OpenAPI specification to align with actual production response payloads.",
                        "Add contract-testing CI gates to detect schema drift before deployment."
                    ],
                    code_fix_example="class SanitizedResponse(BaseModel):\n    # Only declare explicitly permitted fields\n    id: int\n    model: str\n    class Config:\n        extra = 'forbid'"
                ))

        return findings
