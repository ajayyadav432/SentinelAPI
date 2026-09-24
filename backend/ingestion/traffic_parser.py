import json
import urllib.parse
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class TrafficEntry(BaseModel):
    url: str
    method: str
    path: str
    status: int
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    auth_token: Optional[str] = None

class DiscoveredEndpoint(BaseModel):
    method: str
    path_template: str
    example_path: str
    observed_statuses: List[int] = Field(default_factory=list)
    query_params: List[str] = Field(default_factory=list)
    sample_request_headers: Dict[str, str] = Field(default_factory=dict)
    sample_tokens: List[str] = Field(default_factory=list)
    has_id: bool = False

class TrafficParser:
    """Parses HAR files or proxy traffic logs to reconstruct API surface."""

    @staticmethod
    def parse_har(har_content: str) -> List[DiscoveredEndpoint]:
        data = json.loads(har_content)
        entries = data.get("log", {}).get("entries", [])
        
        discovered_map: Dict[str, DiscoveredEndpoint] = {}

        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            
            raw_url = req.get("url", "")
            method = req.get("method", "GET").upper()
            status = resp.get("status", 0)

            parsed_url = urllib.parse.urlparse(raw_url)
            path = parsed_url.path

            # Skip static assets
            if any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".ico", ".svg", ".woff", ".html"]):
                continue

            headers_dict = {h["name"].lower(): h["value"] for h in req.get("headers", []) if "name" in h}
            
            # Extract auth token if any
            auth_val = headers_dict.get("authorization", "")
            token = None
            if auth_val.lower().startswith("bearer "):
                token = auth_val[7:].strip()
            elif auth_val:
                token = auth_val

            # Generalize path numbers/UUIDs into path templates
            parts = path.split("/")
            template_parts = []
            has_id = False
            for part in parts:
                if part.isdigit():
                    template_parts.append("{id}")
                    has_id = True
                elif len(part) in (32, 36) and ("-" in part or part.isalnum()):
                    template_parts.append("{uuid}")
                    has_id = True
                else:
                    template_parts.append(part)
            
            template_path = "/".join(template_parts)
            key = f"{method}:{template_path}"

            query_names = [q.get("name") for q in req.get("queryString", []) if "name" in q]

            if key not in discovered_map:
                discovered_map[key] = DiscoveredEndpoint(
                    method=method,
                    path_template=template_path,
                    example_path=path,
                    observed_statuses=[status] if status else [],
                    query_params=query_names,
                    sample_request_headers=headers_dict,
                    sample_tokens=[token] if token else [],
                    has_id=has_id
                )
            else:
                ep = discovered_map[key]
                if status and status not in ep.observed_statuses:
                    ep.observed_statuses.append(status)
                for q in query_names:
                    if q not in ep.query_params:
                        ep.query_params.append(q)
                if token and token not in ep.sample_tokens:
                    ep.sample_tokens.append(token)

        return list(discovered_map.values())
