import asyncio
import time
from typing import Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field

class HttpResponseResult(BaseModel):
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = ""
    json_data: Optional[Any] = None
    response_time_ms: float = 0.0
    curl_command: str = ""
    error: Optional[str] = None

class AsyncHttpClient:
    """Async HTTP engine for executing security audit requests with concurrency controls."""

    def __init__(self, base_url: str, timeout: float = 8.0, max_concurrency: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False  # Allow testing local / self-signed HTTPS environments
        )

    async def close(self):
        await self.client.aclose()

    @staticmethod
    def build_curl(method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> str:
        parts = ["curl", "-i", "-X", method, f"'{url}'"]
        for k, v in headers.items():
            parts.extend(["-H", f"'{k}: {v}'"])
        if body:
            clean_body = body.replace("'", "'\\''")
            parts.extend(["--data", f"'{clean_body}'"])
        return " ".join(parts)

    async def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        raw_body: Optional[str] = None,
        token: Optional[str] = None,
        auth_type: str = "Bearer"
    ) -> HttpResponseResult:
        req_headers = dict(headers or {})
        if token:
            req_headers["Authorization"] = f"{auth_type} {token}" if auth_type else token
        
        full_url = path if path.startswith("http://") or path.startswith("https://") else f"{self.base_url}{path}"
        
        body_str = None
        if json_body is not None:
            import json
            body_str = json.dumps(json_body)
            req_headers.setdefault("Content-Type", "application/json")
        elif raw_body is not None:
            body_str = raw_body

        curl_cmd = self.build_curl(method, full_url, req_headers, body_str)

        async with self.semaphore:
            start_t = time.perf_counter()
            try:
                resp = await self.client.request(
                    method=method,
                    url=full_url,
                    headers=req_headers,
                    params=params,
                    content=body_str.encode("utf-8") if body_str else None
                )
                elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                
                resp_text = resp.text
                resp_json = None
                try:
                    resp_json = resp.json()
                except Exception:
                    pass

                return HttpResponseResult(
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=resp_text,
                    json_data=resp_json,
                    response_time_ms=elapsed_ms,
                    curl_command=curl_cmd
                )
            except Exception as e:
                elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                return HttpResponseResult(
                    status_code=0,
                    error=str(e),
                    response_time_ms=elapsed_ms,
                    curl_command=curl_cmd
                )
