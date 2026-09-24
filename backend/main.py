import os
import uuid
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.ingestion.spec_parser import SpecParser, ParsedSpec
from backend.engine.scheduler import ScanScheduler
from backend.reporting.finding import ScanSummary
from backend.reporting.report_gen import ReportGenerator
from backend.sandbox.vulnerable_api import create_vulnerable_target_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.main")

app = FastAPI(
    title="SentinelAPI — Zero-Trust API Vulnerability Scanner",
    version="1.0.0",
    description="AI-augmented zero-trust security testing engine for modern REST APIs."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the sandbox target app so tests can point to internal sandbox directly
sandbox_app = create_vulnerable_target_app()
app.mount("/sandbox-target", sandbox_app)

# Active scan storage
ACTIVE_SCANS: Dict[str, ScanSummary] = {}
ACTIVE_WEBSOCKETS: Dict[str, list[WebSocket]] = {}

class ScanRequest(BaseModel):
    spec_content: Optional[str] = None
    target_base_url: str = "http://127.0.0.1:8000/sandbox-target"
    user_a_token: Optional[str] = None
    user_b_token: Optional[str] = None
    admin_token: Optional[str] = None
    gemini_api_key: Optional[str] = None

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "SentinelAPI",
        "version": "1.0.0",
        "gemini_env_detected": bool(os.environ.get("GEMINI_API_KEY"))
    }

@app.get("/api/demo/spec")
def get_demo_spec():
    spec_path = os.path.join(os.path.dirname(__file__), "sandbox", "crapi_openapi.yaml")
    if os.path.exists(spec_path):
        with open(spec_path, "r") as f:
            return {"spec": f.read()}
    return {"spec": ""}

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in ACTIVE_WEBSOCKETS:
        ACTIVE_WEBSOCKETS[scan_id] = []
    ACTIVE_WEBSOCKETS[scan_id].append(websocket)
    try:
        while True:
            # Keep-alive
            msg = await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in ACTIVE_WEBSOCKETS and websocket in ACTIVE_WEBSOCKETS[scan_id]:
            ACTIVE_WEBSOCKETS[scan_id].remove(websocket)

async def broadcast_progress(scan_id: str, data: Dict[str, Any]):
    if scan_id in ACTIVE_WEBSOCKETS:
        dead_sockets = []
        for ws in ACTIVE_WEBSOCKETS[scan_id]:
            try:
                await ws.send_json(data)
            except Exception:
                dead_sockets.append(ws)
        for dead in dead_sockets:
            ACTIVE_WEBSOCKETS[scan_id].remove(dead)

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    
    # Load spec
    spec_text = req.spec_content
    if not spec_text:
        # Load default demo spec
        spec_path = os.path.join(os.path.dirname(__file__), "sandbox", "crapi_openapi.yaml")
        with open(spec_path, "r") as f:
            spec_text = f.read()

    try:
        spec_dict = SpecParser.parse_content(spec_text)
        parsed_spec = SpecParser.parse_spec(spec_dict, default_base_url=req.target_base_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid OpenAPI spec: {str(e)}")

    target_url = req.target_base_url or parsed_spec.base_url or "http://127.0.0.1:8000/sandbox-target"

    # Async background task execution
    async def run_scan_worker():
        async def on_progress(event: Dict[str, Any]):
            await broadcast_progress(scan_id, event)

        scheduler = ScanScheduler(
            base_url=target_url,
            user_a_token=req.user_a_token,
            user_b_token=req.user_b_token,
            admin_token=req.admin_token,
            gemini_api_key=req.gemini_api_key or os.environ.get("GEMINI_API_KEY"),
            progress_callback=on_progress
        )

        try:
            summary = await scheduler.execute_scan(parsed_spec, scan_id)
            ACTIVE_SCANS[scan_id] = summary
            await broadcast_progress(scan_id, {
                "type": "scan_complete",
                "summary": summary.model_dump()
            })
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            await broadcast_progress(scan_id, {
                "type": "scan_error",
                "error": str(e)
            })

    asyncio.create_task(run_scan_worker())

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "endpoints_count": len(parsed_spec.endpoints),
        "status": "running"
    }

@app.get("/api/scan/{scan_id}/summary")
def get_scan_summary(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Scan not found or still running.")
    return ACTIVE_SCANS[scan_id]

@app.get("/api/scan/{scan_id}/report.html")
def get_html_report(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Scan not found or still running.")
    html_content = ReportGenerator.generate_html_report(ACTIVE_SCANS[scan_id])
    return HTMLResponse(content=html_content)

@app.get("/api/scan/{scan_id}/report.json")
def get_json_report(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Scan not found or still running.")
    return ACTIVE_SCANS[scan_id].model_dump()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
