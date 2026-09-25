import os
import json
import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("sentinel.ai")

class GeminiSecurityBrain:
    """Zero-trust AI reasoning engine using Gemini 2.0 Flash with automated local fallback."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = "gemini-3.8-flash"
        self.endpoint_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 10)

    async def _call_gemini(self, prompt: str, system_instruction: Optional[str] = None) -> Optional[str]:
        if not self.is_configured():
            return None

        url = f"{self.endpoint_url}?key={self.api_key}"
        contents = [{"parts": [{"text": prompt}]}]
        body: Dict[str, Any] = {"contents": contents}

        if system_instruction:
            body["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        # Request structured JSON
        body["generationConfig"] = {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(url, json=body)
                if res.status_code == 200:
                    resp_json = res.json()
                    candidates = resp_json.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                else:
                    logger.warning(f"Gemini API returned status {res.status_code}: {res.text[:200]}")
        except Exception as e:
            logger.error(f"Error querying Gemini API: {e}")
        return None

    async def analyze_spec_risks(self, spec_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes API spec to discover authorization attack surfaces and critical paths."""
        system_prompt = (
            "You are an elite AppSec and Zero-Trust API penetration tester. "
            "Analyze the provided API specification endpoints and return JSON with keys: "
            "'high_risk_endpoints' (list of path strings), 'auth_matrix_recommendations' (list of objects), "
            "'sensitive_data_exposure_warnings' (list of strings), and 'attack_strategy_summary' (string)."
        )
        prompt = (
            f"API Title: {spec_summary.get('title')}\n"
            f"Endpoints: {json.dumps(spec_summary.get('endpoints', [])[:35])}\n"
            "Identify likely BOLA/IDOR paths, admin endpoints prone to BFLA, and unauthenticated traps."
        )

        raw_response = await self._call_gemini(prompt, system_prompt)
        if raw_response:
            try:
                return json.loads(raw_response)
            except Exception:
                pass

        # Intelligent Heuristic Fallback
        endpoints = spec_summary.get("endpoints", [])
        high_risk = []
        for ep in endpoints:
            p = ep.get("path", "")
            if "{" in p and ("id" in p.lower() or "user" in p.lower() or "order" in p.lower() or "vehicle" in p.lower()):
                high_risk.append(p)
            elif any(k in p.lower() for k in ["admin", "internal", "config", "debug"]):
                high_risk.append(p)

        return {
            "high_risk_endpoints": high_risk[:10],
            "auth_matrix_recommendations": [
                {"category": "BOLA/IDOR", "rule": "Verify resource ownership check exists in database layer for all /{id} routes."},
                {"category": "BFLA", "rule": "Enforce strict RBAC middleware on administrative /admin routes."},
                {"category": "Excessive Data", "rule": "Use DTO/Serialization filters to avoid leaking PII and password hashes."}
            ],
            "sensitive_data_exposure_warnings": [
                "User profile endpoints may expose password_hash, tokens, and internal IDs",
                "Community/orders endpoints may leak customer emails and physical addresses"
            ],
            "attack_strategy_summary": "Zero-trust verification requires cross-account token swapping (User A vs User B) on resource paths, admin role escalation tests, and token striping."
        }

    async def generate_smart_idor_ids(self, param_name: str, sample_id: Optional[str] = None) -> List[str]:
        """Generates smart parameter values for IDOR testing."""
        candidates = ["1", "2", "3", "0", "-1", "99999", "1000", "admin", "null", "undefined"]
        if sample_id and sample_id.isdigit():
            val = int(sample_id)
            candidates = [str(val - 1), str(val + 1), str(val + 10), "1", "0", "-1", "9999"]
        elif sample_id and ("-" in sample_id or len(sample_id) > 16):
            # UUID-like pattern
            candidates = [
                sample_id[:-1] + "0",
                sample_id[:-1] + "1",
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "1"
            ]
        return candidates

    async def explain_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a comprehensive executive and developer remediation for a finding."""
        vuln_type = finding.get("vuln_type", "Unknown")
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        evidence = finding.get("evidence", "")

        system_prompt = (
            "You are a Principal Security Architect. Provide an authoritative vulnerability explanation and remediation. "
            "Return JSON with keys: 'plain_english_summary', 'business_impact', 'remediation_steps' (list of 3 concrete actions), 'code_fix_example' (Python/FastAPI or Node.js snippet)."
        )
        prompt = (
            f"Vulnerability: {vuln_type}\n"
            f"Endpoint: {method} {endpoint}\n"
            f"Evidence: {evidence}\n"
            "Explain what happened, why it's critical, and provide exact code fixes."
        )

        raw_response = await self._call_gemini(prompt, system_prompt)
        if raw_response:
            try:
                return json.loads(raw_response)
            except Exception:
                pass

        # Intelligent Built-in AppSec Explanations
        if "BOLA" in vuln_type or "IDOR" in vuln_type:
            return {
                "plain_english_summary": f"An authenticated user successfully accessed another user's private resource via {method} {endpoint} without permission verification.",
                "business_impact": "Direct data leakage violating GDPR/CCPA, enabling account takeover or bulk exfiltration of customer records.",
                "remediation_steps": [
                    "Validate that the authenticated session user ID matches the owner_id of the requested resource in the database query.",
                    "Replace guessable sequential integer IDs with cryptographically secure UUIDv4 identifiers.",
                    "Adopt an API Gateway or Zero-Trust Authorization policy (e.g. OPA / Cedar) to enforce object-level ownership checks."
                ],
                "code_fix_example": "@app.get('/resource/{id}')\ndef get_resource(id: int, current_user = Depends(get_current_user)):\n    item = db.query(Resource).filter_by(id=id, owner_id=current_user.id).first()\n    if not item:\n        raise HTTPException(status_code=404, detail='Not found')\n    return item"
            }
        elif "BFLA" in vuln_type:
            return {
                "plain_english_summary": f"A regular, low-privileged user or unauthenticated client successfully invoked an administrative operation at {method} {endpoint}.",
                "business_impact": "Privilege escalation allowing unauthorized modification of system configurations, user deletion, or system compromise.",
                "remediation_steps": [
                    "Enforce Role-Based Access Control (RBAC) middleware verifying 'admin' role before executing route logic.",
                    "Deny access by default: explicit permission decorators must be attached to all sensitive endpoints.",
                    "Audit API route registration to ensure internal/admin endpoints are not exposed to external public interfaces."
                ],
                "code_fix_example": "def require_admin(user: User = Depends(get_current_user)):\n    if user.role != 'admin':\n        raise HTTPException(status_code=403, detail='Insufficient permissions')\n    return user"
            }
        elif "Excessive Data Exposure" in vuln_type:
            return {
                "plain_english_summary": f"The response from {method} {endpoint} contains sensitive internal attributes (passwords, tokens, or PII) that should not be visible to clients.",
                "business_impact": "Credential harvesting, identity theft, or reconnaissance enabling secondary lateral attacks.",
                "remediation_steps": [
                    "Implement response data transfer objects (DTOs / Pydantic schemas) with explicit field whitelisting.",
                    "Never serialize raw ORM database models directly to client responses.",
                    "Strip sensitive keys (e.g., password_hash, ssn, secret_key) via centralized response interceptors."
                ],
                "code_fix_example": "class UserPublicResponse(BaseModel):\n    id: int\n    username: str\n    # EXCLUDE: password_hash, secret_pin, internal_notes\n    class Config:\n        from_attributes = True"
            }
        elif "Rate Limit" in vuln_type:
            return {
                "plain_english_summary": f"The endpoint {method} {endpoint} accepted high-frequency concurrent requests without throttling or returning HTTP 429.",
                "business_impact": "Susceptible to credential stuffing, brute-force OTP attacks, denial of service, and server resource exhaustion.",
                "remediation_steps": [
                    "Implement token bucket / sliding window rate limiting per IP and per authenticated user.",
                    "Return HTTP 429 Too Many Requests with a 'Retry-After' header when limits are exceeded.",
                    "Deploy Cloudflare / reverse proxy WAF rate limiting on authentication and sensitive endpoints."
                ],
                "code_fix_example": "# Using SlowAPI / Redis Rate Limiter:\n@limiter.limit('5/minute')\n@app.post('/api/auth/login')\ndef login():\n    ..."
            }
        else:
            return {
                "plain_english_summary": f"Security misconfiguration or lack of zero-trust verification detected at {method} {endpoint}.",
                "business_impact": "Weakens defense-in-depth posture and exposes the API to automated reconnaissance.",
                "remediation_steps": [
                    "Configure strict CORS headers (`Access-Control-Allow-Origin` specific origin, not `*` with credentials).",
                    "Add security headers: X-Content-Type-Options: nosniff, Content-Security-Policy.",
                    "Suppress verbose stack traces in production error responses."
                ],
                "code_fix_example": "app.add_middleware(\n    CORSMiddleware,\n    allow_origins=['https://app.yourdomain.com'],\n    allow_credentials=True,\n    allow_methods=['GET', 'POST'],\n    allow_headers=['Authorization', 'Content-Type']\n)"
            }
