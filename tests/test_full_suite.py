import asyncio
import os
import pytest
from backend.ingestion.spec_parser import SpecParser
from backend.engine.http_client import AsyncHttpClient
from backend.engine.session_manager import SessionManager
from backend.ai.gemini_client import GeminiSecurityBrain
from backend.ai.agent import AutonomousPentestAgent
from backend.scanners.idor_scanner import IdorScanner
from backend.scanners.bfla_scanner import BflaScanner
from backend.scanners.data_exposure import DataExposureScanner
from backend.scanners.rate_limit import RateLimitScanner
from backend.scanners.misconfig import MisconfigScanner
from backend.reporting.report_gen import ReportGenerator
from backend.engine.scheduler import ScanScheduler

BASE_URL = "http://127.0.0.1:8000/sandbox-target"

@pytest.fixture(scope="module")
def parsed_spec():
    spec_path = "backend/sandbox/crapi_openapi.yaml"
    with open(spec_path, "r") as f:
        content = f.read()
    spec_dict = SpecParser.parse_content(content)
    return SpecParser.parse_spec(spec_dict, default_base_url=BASE_URL)

@pytest.mark.asyncio
async def test_spec_parser(parsed_spec):
    assert len(parsed_spec.endpoints) >= 5
    paths = [ep.path for ep in parsed_spec.endpoints]
    assert "/community/posts" in paths
    assert "/identity/api/v2/vehicle/{vehicle_id}/location" in paths

@pytest.mark.asyncio
async def test_idor_scanner(parsed_spec):
    http_client = AsyncHttpClient(base_url=BASE_URL)
    session_mgr = SessionManager()
    ai_brain = GeminiSecurityBrain()
    scanner = IdorScanner(http_client, session_mgr, ai_brain)

    ep = next(e for e in parsed_spec.endpoints if "{vehicle_id}" in e.path)
    findings = await scanner.scan_endpoint(ep)
    await http_client.close()

    assert len(findings) > 0
    assert any(f.category == "BOLA" for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)

@pytest.mark.asyncio
async def test_bfla_scanner(parsed_spec):
    http_client = AsyncHttpClient(base_url=BASE_URL)
    session_mgr = SessionManager()
    ai_brain = GeminiSecurityBrain()
    scanner = BflaScanner(http_client, session_mgr, ai_brain)

    admin_ep = next(e for e in parsed_spec.endpoints if "admin" in e.path.lower())
    findings = await scanner.scan_endpoint(admin_ep)
    await http_client.close()

    assert len(findings) > 0
    assert any(f.category == "BFLA" for f in findings)

@pytest.mark.asyncio
async def test_data_exposure_scanner(parsed_spec):
    http_client = AsyncHttpClient(base_url=BASE_URL)
    session_mgr = SessionManager()
    ai_brain = GeminiSecurityBrain()
    scanner = DataExposureScanner(http_client, session_mgr, ai_brain)

    profile_ep = next(e for e in parsed_spec.endpoints if "profile" in e.path.lower())
    findings = await scanner.scan_endpoint(profile_ep)
    await http_client.close()

    assert len(findings) > 0
    assert any(f.category == "DATA_EXPOSURE" for f in findings)

@pytest.mark.asyncio
async def test_misconfig_scanner(parsed_spec):
    http_client = AsyncHttpClient(base_url=BASE_URL)
    session_mgr = SessionManager()
    ai_brain = GeminiSecurityBrain()
    scanner = MisconfigScanner(http_client, session_mgr, ai_brain)

    posts_ep = next(e for e in parsed_spec.endpoints if "posts" in e.path.lower())
    findings = await scanner.scan_endpoint(posts_ep)
    await http_client.close()

    assert len(findings) > 0
    assert any(f.category == "MISCONFIG" for f in findings)

@pytest.mark.asyncio
async def test_agentic_chain(parsed_spec):
    http_client = AsyncHttpClient(base_url=BASE_URL)
    session_mgr = SessionManager()
    ai_brain = GeminiSecurityBrain()
    agent = AutonomousPentestAgent(http_client, session_mgr, ai_brain)

    chain = await agent.run_autonomous_chain(parsed_spec)
    await http_client.close()

    assert chain is not None
    assert chain.status == "SUCCESSFUL_EXPLOIT"
    assert len(chain.steps) >= 2

@pytest.mark.asyncio
async def test_full_scheduler_and_report(parsed_spec):
    scheduler = ScanScheduler(base_url=BASE_URL)
    summary = await scheduler.execute_scan(parsed_spec, "test-suite-scan-1")

    assert summary.findings_count > 0
    assert summary.critical_count > 0
    assert summary.overall_risk_score > 50.0

    html = ReportGenerator.generate_html_report(summary)
    assert "SentinelAPI Zero-Trust Security Audit" in html
    assert "test-suite-scan-1" in html

if __name__ == "__main__":
    asyncio.run(test_idor_scanner(None))
