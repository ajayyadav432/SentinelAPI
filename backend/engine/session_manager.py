from typing import Dict, Optional, List
from pydantic import BaseModel, Field

class UserProfile(BaseModel):
    user_id: str
    username: str
    email: str
    role: str = "user"  # "user", "admin", "manager", "guest"
    token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    known_resource_ids: List[str] = Field(default_factory=list)

class SessionManager:
    """Manages multi-tenant identity contexts for authorization cross-testing (BOLA/BFLA)."""

    def __init__(self, user_a_token: Optional[str] = None, user_b_token: Optional[str] = None, admin_token: Optional[str] = None):
        self.user_a = UserProfile(
            user_id="user_a_victim",
            username="victim_user",
            email="alice@sentinel.local",
            role="user",
            token=user_a_token or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.victim_token_mock_A",
            known_resource_ids=["1", "42", "101", "1001", "usr_998811"]
        )
        self.user_b = UserProfile(
            user_id="user_b_attacker",
            username="attacker_user",
            email="bob@sentinel.local",
            role="user",
            token=user_b_token or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.attacker_token_mock_B",
            known_resource_ids=["2", "43", "102", "1002", "usr_998822"]
        )
        self.admin = UserProfile(
            user_id="admin_user",
            username="admin_sys",
            email="admin@sentinel.local",
            role="admin",
            token=admin_token or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token_mock",
            known_resource_ids=["0", "1", "2"]
        )
        self.anonymous = UserProfile(
            user_id="anonymous",
            username="guest",
            email="anon@sentinel.local",
            role="guest",
            token=None
        )

    def set_user_a(self, token: str, known_ids: Optional[List[str]] = None):
        self.user_a.token = token
        if known_ids:
            self.user_a.known_resource_ids = known_ids

    def set_user_b(self, token: str, known_ids: Optional[List[str]] = None):
        self.user_b.token = token
        if known_ids:
            self.user_b.known_resource_ids = known_ids

    def set_admin(self, token: str):
        self.admin.token = token
