import datetime
import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"VULN-{uuid.uuid4().hex[:8].upper()}")
    vuln_type: str
    category: str  # BOLA, BFLA, DATA_EXPOSURE, RATE_LIMIT, MISCONFIG
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float = 7.5
    owasp_tag: str = "API1:2023"
    endpoint: str
    method: str
    evidence: str
    reproduction_curl: str = ""
    attacker_token_used: Optional[str] = None
    target_resource_id: Optional[str] = None
    status_code_observed: int = 200
    response_snippet: Optional[str] = None
    plain_english_summary: str = ""
    business_impact: str = ""
    remediation_steps: List[str] = Field(default_factory=list)
    code_fix_example: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class ScanSummary(BaseModel):
    scan_id: str
    target_url: str
    total_endpoints: int = 0
    scanned_endpoints: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_score: float = 0.0  # 0 to 100
    duration_seconds: float = 0.0
    status: str = "running"  # pending, running, completed, failed
    findings: List[Finding] = Field(default_factory=list)
    ai_risk_overview: Optional[Dict[str, Any]] = None
