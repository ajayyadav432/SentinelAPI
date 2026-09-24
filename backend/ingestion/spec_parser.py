import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional
import yaml
from pydantic import BaseModel, Field

class ParameterInfo(BaseModel):
    name: str
    in_location: str  # "path", "query", "header", "cookie"
    required: bool = False
    param_type: str = "string"
    description: Optional[str] = None
    example: Optional[Any] = None

class EndpointInfo(BaseModel):
    id: str
    path: str
    method: str
    summary: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    parameters: List[ParameterInfo] = Field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    responses: Dict[str, Any] = Field(default_factory=dict)
    security: List[Dict[str, List[str]]] = Field(default_factory=list)
    requires_auth: bool = True
    has_path_id: bool = False
    id_param_names: List[str] = Field(default_factory=list)
    category: str = "general"
    risk_level: str = "low"  # low, medium, high, critical

class ParsedSpec(BaseModel):
    title: str = "API Specification"
    version: str = "1.0.0"
    base_url: str = ""
    endpoints: List[EndpointInfo] = Field(default_factory=list)
    security_schemes: Dict[str, Any] = Field(default_factory=dict)
    raw_spec: Dict[str, Any] = Field(default_factory=dict)

class SpecParser:
    """Parses OpenAPI 2.0/3.0/3.1 specs from string, dict, or file."""

    @staticmethod
    def parse_content(raw_text: str) -> Dict[str, Any]:
        """Tries parsing JSON then YAML."""
        raw_text = raw_text.strip()
        if raw_text.startswith("{") or raw_text.startswith("["):
            try:
                return json.loads(raw_text)
            except Exception:
                pass
        return yaml.safe_load(raw_text)

    @classmethod
    def resolve_ref(cls, ref: str, root_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves local #/components/schemas/... or #/definitions/... refs."""
        if not ref.startswith("#/"):
            return {}
        parts = ref.lstrip("#/").split("/")
        curr = root_doc
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return {}
        return curr if isinstance(curr, dict) else {}

    @classmethod
    def parse_spec(cls, spec_data: Dict[str, Any], default_base_url: str = "") -> ParsedSpec:
        info = spec_data.get("info", {})
        title = info.get("title", "API Service")
        version = info.get("version", "1.0.0")

        # Base URL extraction
        base_url = default_base_url
        if not base_url:
            if "servers" in spec_data and spec_data["servers"]:
                base_url = spec_data["servers"][0].get("url", "")
            elif "host" in spec_data:
                schemes = spec_data.get("schemes", ["http"])
                base_url = f"{schemes[0]}://{spec_data['host']}{spec_data.get('basePath', '')}"

        # Clean base_url
        if base_url.endswith("/"):
            base_url = base_url.rstrip("/")

        # Security schemes
        security_schemes = {}
        if "components" in spec_data and "securitySchemes" in spec_data["components"]:
            security_schemes = spec_data["components"]["securitySchemes"]
        elif "securityDefinitions" in spec_data:
            security_schemes = spec_data["securityDefinitions"]

        global_security = spec_data.get("security", [])

        paths = spec_data.get("paths", {})
        endpoints: List[EndpointInfo] = []

        id_regex = re.compile(r"\{([^}]+)\}")

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_params = path_item.get("parameters", [])

            for method_raw, operation in path_item.items():
                method = method_raw.upper()
                if method not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                    continue

                summary = operation.get("summary")
                description = operation.get("description")
                tags = operation.get("tags", [])
                
                # Check path variables
                path_vars = id_regex.findall(path)
                has_path_id = len(path_vars) > 0

                # Merge parameters
                op_params = operation.get("parameters", [])
                combined_params = []
                for p in path_params + op_params:
                    if "$ref" in p:
                        resolved = cls.resolve_ref(p["$ref"], spec_data)
                        if resolved:
                            p = resolved
                    
                    schema = p.get("schema", {})
                    p_type = schema.get("type", p.get("type", "string"))
                    combined_params.append(ParameterInfo(
                        name=p.get("name", "param"),
                        in_location=p.get("in", "query"),
                        required=p.get("required", False),
                        param_type=p_type,
                        description=p.get("description"),
                        example=p.get("example")
                    ))

                # Identify ID parameter names
                id_names = [p for p in path_vars]
                for p in combined_params:
                    low_name = p.name.lower()
                    if any(term in low_name for term in ["id", "uuid", "account", "user", "order", "vin", "card", "vehicle", "token", "key"]):
                        if p.name not in id_names:
                            id_names.append(p.name)

                # Security & auth requirement
                op_security = operation.get("security", global_security)
                requires_auth = len(op_security) > 0 if op_security is not None else False
                
                # Request body schema extraction
                request_body = operation.get("requestBody", {})
                req_schema = None
                if request_body:
                    content = request_body.get("content", {})
                    json_media = content.get("application/json", {})
                    req_schema = json_media.get("schema")
                    if req_schema and "$ref" in req_schema:
                        req_schema = cls.resolve_ref(req_schema["$ref"], spec_data)

                # Categorize and estimate risk
                path_lower = path.lower()
                category = "general"
                risk_level = "low"

                if any(x in path_lower for x in ["auth", "login", "register", "token", "password", "session"]):
                    category = "authentication"
                    risk_level = "critical"
                elif any(x in path_lower for x in ["admin", "internal", "root", "system", "manage", "role", "permissions"]):
                    category = "administration"
                    risk_level = "critical"
                elif any(x in path_lower for x in ["user", "account", "profile", "member", "customer"]):
                    category = "identity"
                    risk_level = "high" if has_path_id else "medium"
                elif any(x in path_lower for x in ["order", "vehicle", "car", "post", "message", "cart", "document", "file", "invoice"]):
                    category = "resource"
                    risk_level = "high" if has_path_id else "medium"
                elif any(x in path_lower for x in ["payment", "billing", "card", "wallet", "checkout", "transaction"]):
                    category = "financial"
                    risk_level = "critical"

                ep_id = f"{method}_{re.sub(r'[^a-zA-Z0-9]', '_', path).strip('_')}"

                endpoints.append(EndpointInfo(
                    id=ep_id,
                    path=path,
                    method=method,
                    summary=summary,
                    description=description,
                    tags=tags,
                    parameters=combined_params,
                    request_body_schema=req_schema,
                    responses=operation.get("responses", {}),
                    security=op_security if op_security else [],
                    requires_auth=requires_auth,
                    has_path_id=has_path_id,
                    id_param_names=id_names,
                    category=category,
                    risk_level=risk_level
                ))

        return ParsedSpec(
            title=title,
            version=version,
            base_url=base_url,
            endpoints=endpoints,
            security_schemes=security_schemes,
            raw_spec=spec_data
        )
