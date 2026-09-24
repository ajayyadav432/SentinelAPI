"""
Built-in realistic Vulnerable Target API (crAPI / DVAPI equivalent).
Runs on an internal port or embedded in the demo so judges can test
real zero-trust vulnerabilities instantly with zero external setup.
"""
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any

def create_vulnerable_target_app() -> FastAPI:
    app = FastAPI(
        title="Automotive Cloud Service (Target API)",
        version="2.4.0",
        description="Target microservice containing seeded OWASP API Top 10 vulnerabilities for testing zero-trust scanners."
    )

    # Seeded Misconfiguration 1: Permissive CORS with credentials
    @app.middleware("http")
    async def cors_leak_middleware(request: Request, call_next):
        origin = request.headers.get("origin", "*")
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        return response

    # Mock Database
    USERS_DB = {
        "user_a_victim": {
            "id": 1,
            "username": "alice_victim",
            "email": "alice@customer.com",
            "role": "user",
            "password_hash": "$2b$12$e8J4Hn9z.kR91qWwPq2xNuL52x0/9O3W8sB4aF3j9qQ",
            "secret_pin": "9921",
            "balance": 14250.00
        },
        "user_b_attacker": {
            "id": 2,
            "username": "bob_attacker",
            "email": "bob@attacker.com",
            "role": "user",
            "password_hash": "$2b$12$Z0w.Y2L/5qM7m9n4V8k3NuK52x0/9O3W8sB4aF3j9qQ",
            "secret_pin": "1234",
            "balance": 50.00
        }
    }

    VEHICLES_DB = {
        "1": {
            "vehicle_id": "1",
            "owner_id": 1,
            "owner_name": "Alice Customer",
            "vin": "1HGCR2F83HA001234",
            "model": "Apex CyberSedan 2026",
            "gps_latitude": 37.7749,
            "gps_longitude": -122.4194,
            "status": "active_driving",
            "battery_level": "87%"
        },
        "2": {
            "vehicle_id": "2",
            "owner_id": 2,
            "owner_name": "Bob Attacker",
            "vin": "2T1BURHE5JC005678",
            "model": "Apex CargoVan 2025",
            "gps_latitude": 40.7128,
            "gps_longitude": -74.0060,
            "status": "parked",
            "battery_level": "42%"
        }
    }

    POSTS_DB = [
        {"post_id": 101, "author": "Alice Customer", "author_id": 1, "vehicle_id": "1", "content": "Just got my new vehicle serviced!"},
        {"post_id": 102, "author": "Bob Attacker", "author_id": 2, "vehicle_id": "2", "content": "Any good charging stations around downtown?"}
    ]

    # Endpoint 1: Public Community Feed (Reconnaissance step for agent)
    @app.get("/community/posts")
    def get_posts():
        return {"posts": POSTS_DB}

    # Endpoint 2: Seeded BOLA / IDOR Vulnerability (OWASP API1:2023)
    # The server accepts ANY valid token, but does NOT check if the vehicle belongs to the caller!
    @app.get("/identity/api/v2/vehicle/{vehicle_id}/location")
    def get_vehicle_location(vehicle_id: str, authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
        
        # Flaw: No check that user owns vehicle_id! Returns vehicle directly.
        if vehicle_id in VEHICLES_DB:
            return VEHICLES_DB[vehicle_id]
        raise HTTPException(status_code=404, detail="Vehicle not found")

    # Endpoint 3: Seeded Excessive Data Exposure (OWASP API3:2023)
    # Returns raw database model including password_hash and secret_pin!
    @app.get("/identity/api/v2/user/profile")
    def get_user_profile(authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
        # Leaks password hash and secret pin
        return USERS_DB["user_a_victim"]

    # Endpoint 4: Seeded Broken Function Level Authorization (OWASP API5:2023)
    # Allows standard user or unverified caller to delete users / modify admin settings
    @app.delete("/admin/api/v1/users/{user_id}")
    def admin_delete_user(user_id: int, authorization: Optional[str] = Header(None)):
        # Flaw: Does not check user.role == 'admin'!
        return {"status": "success", "message": f"Administrative action: User {user_id} deleted."}

    @app.get("/admin/api/v1/system/config")
    def admin_get_config(authorization: Optional[str] = Header(None)):
        return {
            "environment": "production",
            "jwt_secret": "super_secret_signing_key_never_share_9921",
            "database_url": "postgresql://postgres:admin123@internal-db:5432/main"
        }

    # Endpoint 5: Seeded Missing Rate Limiting (OWASP API4:2023)
    # Login accepts unlimited brute-force attempts without 429
    @app.post("/auth/api/v1/login")
    def login_endpoint(payload: Optional[Dict[str, Any]] = None):
        return {"status": "ok", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token_1234"}

    return app
