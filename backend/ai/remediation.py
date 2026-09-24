from typing import Dict, Any, Optional
from backend.reporting.finding import Finding
from backend.ai.gemini_client import GeminiSecurityBrain

class PrRemediationEngine:
    """Generates automated Git Pull Request patches and defense-in-depth code diffs."""

    def __init__(self, ai_brain: Optional[GeminiSecurityBrain] = None):
        self.ai = ai_brain or GeminiSecurityBrain()

    def generate_pr_patch(self, finding: Finding) -> Dict[str, Any]:
        """Generates a complete Git Pull Request payload with Unified Diff patch."""
        cat = finding.category
        endpoint = finding.endpoint
        method = finding.method

        if cat == "BOLA":
            title = f"fix(security): enforce zero-trust object ownership on {method} {endpoint}"
            target_file = "app/routers/vehicle.py"
            diff = f"""--- a/{target_file}
+++ b/{target_file}
@@ -14,6 +14,10 @@
-@app.get("/identity/api/v2/vehicle/{{vehicle_id}}/location")
-def get_vehicle_location(vehicle_id: str, authorization: str = Header(...)):
-    return VEHICLES_DB.get(vehicle_id)
+@app.get("/identity/api/v2/vehicle/{{vehicle_id}}/location", response_model=VehicleLocationDTO)
+def get_vehicle_location(vehicle_id: str, current_user: User = Depends(get_current_user)):
+    vehicle = db.query(Vehicle).filter_by(vehicle_id=vehicle_id).first()
+    if not vehicle or vehicle.owner_id != current_user.id:
+        # Return 404 to avoid object enumeration
+        raise HTTPException(status_code=404, detail="Vehicle not found")
+    return vehicle
"""
            summary = (
                f"### Security Advisory (OWASP API1:2023 - BOLA/IDOR)\n\n"
                f"**Vulnerability**: An authenticated user was able to access vehicle coordinates belonging to another tenant.\n\n"
                f"**Fix Description**:\n"
                f"- Replaced raw database lookup with tenant ownership validation (`vehicle.owner_id == current_user.id`).\n"
                f"- Return generic HTTP 404 on ownership failure to prevent ID enumeration attacks."
            )

        elif cat == "BFLA":
            title = f"fix(security): enforce RBAC admin role verification on {method} {endpoint}"
            target_file = "app/routers/admin.py"
            diff = f"""--- a/{target_file}
+++ b/{target_file}
@@ -25,4 +25,8 @@
-@app.delete("/admin/api/v1/users/{{user_id}}")
-def admin_delete_user(user_id: int):
-    return db.delete_user(user_id)
+@app.delete("/admin/api/v1/users/{{user_id}}", dependencies=[Depends(require_admin_role)])
+def admin_delete_user(user_id: int, current_admin: User = Depends(get_current_user)):
+    audit_log(actor=current_admin.id, action="USER_DELETION", target_user=user_id)
+    return db.delete_user(user_id)
"""
            summary = (
                f"### Security Advisory (OWASP API5:2023 - BFLA)\n\n"
                f"**Vulnerability**: Low-privileged callers could execute administrative deletions.\n\n"
                f"**Fix Description**:\n"
                f"- Injected `require_admin_role` dependency middleware verifying user role.\n"
                f"- Added immutable security audit logging for administrative actions."
            )

        elif cat == "DATA_EXPOSURE":
            title = f"fix(security): sanitize response DTO to prevent credential leakage on {method} {endpoint}"
            target_file = "app/schemas/user.py"
            diff = f"""--- a/{target_file}
+++ b/{target_file}
@@ -8,7 +8,6 @@
 class UserProfileResponse(BaseModel):
     id: int
     username: str
     email: str
-    password_hash: str
-    secret_pin: str
+    # Stripped password_hash and secret_pin to eliminate excessive data exposure
     class Config:
         from_attributes = True
"""
            summary = (
                f"### Security Advisory (OWASP API3:2023 - Excessive Data Exposure)\n\n"
                f"**Vulnerability**: Endpoint returned internal password hashes and PINs.\n\n"
                f"**Fix Description**:\n"
                f"- Explicitly excluded `password_hash` and `secret_pin` from public serialization DTO.\n"
                f"- Configured strict Pydantic schema validation."
            )

        elif cat == "RATE_LIMIT":
            title = f"fix(security): implement sliding-window rate limiting on {method} {endpoint}"
            target_file = "app/routers/auth.py"
            diff = f"""--- a/{target_file}
+++ b/{target_file}
@@ -10,3 +10,4 @@
+@limiter.limit("5/minute")
 @app.post("/auth/api/v1/login")
 def login_endpoint(request: Request, payload: LoginDTO):
"""
            summary = (
                f"### Security Advisory (OWASP API4:2023 - Unrestricted Resource Use)\n\n"
                f"**Fix Description**: Enforced 5 requests/minute threshold with Redis sliding-window limiter."
            )

        else:
            title = f"fix(security): harden CORS origin whitelist and security headers on {endpoint}"
            target_file = "app/main.py"
            diff = f"""--- a/{target_file}
+++ b/{target_file}
@@ -15,4 +15,6 @@
-app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
+app.add_middleware(
+    CORSMiddleware,
+    allow_origins=["https://dashboard.sentinel.io"],
+    allow_credentials=True,
+    allow_methods=["GET", "POST"]
+)
"""
            summary = (
                f"### Security Advisory (OWASP API8:2023 - Misconfiguration)\n\n"
                f"**Fix Description**: Removed wildcard `*` with credentials, restricted to explicit domain."
            )

        return {
            "pr_title": title,
            "target_file": target_file,
            "pr_body": summary,
            "git_patch": diff,
            "branch_name": f"sentinel/fix-{finding.category.lower()}-{finding.id[:8].lower()}"
        }
