import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Awaitable
from backend.ingestion.spec_parser import ParsedSpec, EndpointInfo
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.ai.gemini_client import GeminiSecurityBrain
from backend.ai.agent import AutonomousPentestAgent, AgenticExploitResult
from backend.scanners.idor_scanner import IdorScanner
from backend.scanners.bfla_scanner import BflaScanner
from backend.scanners.data_exposure import DataExposureScanner
from backend.scanners.rate_limit import RateLimitScanner
from backend.scanners.misconfig import MisconfigScanner
from backend.reporting.finding import Finding, ScanSummary

logger = logging.getLogger("sentinel.scheduler")

class ScanScheduler:
    """Orchestrates comprehensive multi-threaded zero-trust API scanning."""

    def __init__(
        self,
        base_url: str,
        user_a_token: Optional[str] = None,
        user_b_token: Optional[str] = None,
        admin_token: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.http_client = AsyncHttpClient(base_url=self.base_url)
        self.session_mgr = SessionManager(
            user_a_token=user_a_token,
            user_b_token=user_b_token,
            admin_token=admin_token
        )
        self.ai = GeminiSecurityBrain(api_key=gemini_api_key)
        self.progress_callback = progress_callback
        
        # Scanners
        self.idor_scanner = IdorScanner(self.http_client, self.session_mgr, self.ai)
        self.bfla_scanner = BflaScanner(self.http_client, self.session_mgr, self.ai)
        self.data_scanner = DataExposureScanner(self.http_client, self.session_mgr, self.ai)
        self.rate_scanner = RateLimitScanner(self.http_client, self.session_mgr, self.ai)
        self.misc_scanner = MisconfigScanner(self.http_client, self.session_mgr, self.ai)
        self.agent = AutonomousPentestAgent(self.http_client, self.session_mgr, self.ai)

    async def _emit_progress(self, message: str, percent: float, current_endpoint: str = "", new_finding: Optional[Finding] = None):
        if self.progress_callback:
            try:
                data = {
                    "type": "progress",
                    "message": message,
                    "percent": round(percent, 1),
                    "current_endpoint": current_endpoint,
                    "timestamp": time.time()
                }
                if new_finding:
                    data["type"] = "finding_detected"
                    data["finding"] = new_finding.model_dump()
                await self.progress_callback(data)
            except Exception as e:
                logger.error(f"Error calling progress callback: {e}")

    async def execute_scan(self, spec: ParsedSpec, scan_id: str) -> ScanSummary:
        start_time = time.perf_counter()
        findings: List[Finding] = []
        total_endpoints = len(spec.endpoints)

        await self._emit_progress(f"Parsing API specification: {spec.title} (v{spec.version})", 5.0)

        # 1. AI Spec Intelligence Analysis
        spec_summary = {
            "title": spec.title,
            "version": spec.version,
            "endpoints": [{"path": ep.path, "method": ep.method, "category": ep.category} for ep in spec.endpoints]
        }
        await self._emit_progress("AI Security Brain analyzing authorization topology and attack vectors...", 10.0)
        ai_risk_overview = await self.ai.analyze_spec_risks(spec_summary)

        # 2. Iterate through endpoints with scanners
        scanned_count = 0
        for i, ep in enumerate(spec.endpoints):
            ep_label = f"{ep.method} {ep.path}"
            pct = 15.0 + ((i + 1) / max(total_endpoints, 1)) * 65.0
            await self._emit_progress(f"Scanning endpoint: {ep_label}", pct, current_endpoint=ep_label)

            # Run scanners for this endpoint
            scan_tasks = [
                self.idor_scanner.scan_endpoint(ep),
                self.bfla_scanner.scan_endpoint(ep),
                self.data_scanner.scan_endpoint(ep),
                self.rate_scanner.scan_endpoint(ep),
                self.misc_scanner.scan_endpoint(ep)
            ]

            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    for finding in res:
                        findings.append(finding)
                        await self._emit_progress(
                            f"Vulnerability Discovered: {finding.vuln_type} on {finding.endpoint}",
                            pct,
                            current_endpoint=ep_label,
                            new_finding=finding
                        )

            scanned_count += 1
            # Small yield for async loop
            await asyncio.sleep(0.01)

        # 3. Autonomous Pentest Agentic Chain
        await self._emit_progress("Launching Autonomous Pentest Agent for multi-step exploit chaining...", 85.0)
        agentic_chain = await self.agent.run_autonomous_chain(spec)

        await self._emit_progress("Finalizing risk scoring and generating remediation matrix...", 95.0)
        await self.http_client.close()

        # Compute counts & risk score
        crit = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        med = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")

        # Risk score calculation (0 - 100)
        risk_score = min(100.0, round((crit * 25.0) + (high * 15.0) + (med * 8.0) + (low * 3.0), 1))
        if crit > 0 and risk_score < 75.0:
            risk_score = 85.0

        duration = round(time.perf_counter() - start_time, 2)

        summary = ScanSummary(
            scan_id=scan_id,
            target_url=self.base_url,
            total_endpoints=total_endpoints,
            scanned_endpoints=scanned_count,
            findings_count=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            overall_risk_score=risk_score,
            duration_seconds=duration,
            status="completed",
            findings=findings,
            ai_risk_overview={
                **ai_risk_overview,
                "agentic_chain": agentic_chain.model_dump() if agentic_chain else None
            }
        )

        await self._emit_progress(f"Scan complete! {len(findings)} vulnerabilities identified in {duration}s.", 100.0)
        return summary
