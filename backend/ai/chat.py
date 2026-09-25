import json
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from backend.ai.gemini_client import GeminiSecurityBrain

logger = logging.getLogger("sentinel.chat")

class ChatMessage(BaseModel):
    role: str  # "user" or "assistant" or "system"
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    scan_id: Optional[str] = None
    finding_context: Optional[Dict[str, Any]] = None
    gemini_api_key: Optional[str] = None  # matches main.py and frontend api_key field
    language: str = "en"
    mode: str = "developer"

class ChatResponse(BaseModel):
    reply: str
    suggested_actions: List[str] = Field(default_factory=list)
    auto_speak: bool = False

class PentestChatbot:
    """Security Copilot that answers developer queries, explains exploit mechanics, and generates custom patches."""

    def __init__(self, ai_brain: Optional[GeminiSecurityBrain] = None):
        self.ai = ai_brain or GeminiSecurityBrain()

    async def chat(self, request: ChatRequest, scan_summary: Optional[Dict[str, Any]] = None) -> ChatResponse:
        user_msg = request.messages[-1].content if request.messages else "Hello"
        finding_ctx = request.finding_context or {}
        low_q = user_msg.lower()
        auto_speak = "vulnerabilit" in low_q or "explain" in low_q

        # System prompt with rich zero-trust cybersecurity persona
        if request.mode == "client":
            persona = (
                "You are an executive cybersecurity advisor. Your goal is to explain vulnerabilities, security concepts, "
                "and scan results in simple, non-technical layman's terms. Focus on the business impact, risks, "
                "and high-level solutions without using overly complex jargon or code. "
            )
        else:
            persona = (
                "You are SentinelAI, an elite Zero-Trust Application Security Engineer and Pentester. "
                "You specialize in API security, OWASP API Top 10 (2023), BOLA/IDOR, BFLA, and cloud-native architecture. "
                "Help developers understand vulnerabilities, reproduce exploits, explain business impact to leadership, "
                "and write secure code in Python (FastAPI/Django), Node.js (Express), Java (Spring), or Go. "
            )

        lang_instruction = "Respond entirely in Hindi." if request.language == "hi" else "Respond entirely in English."
        scan_instruction = (
            "If the user asks to check or scan vulnerabilities for a specific website URL, respond with a confirmation "
            "and include an action strictly in the format 'SCAN_URL:<the_url>' in your suggested actions."
        )

        system_prompt = f"{persona} {lang_instruction} {scan_instruction}"

        context_prompt = ""
        if finding_ctx:
            context_prompt = (
                f"\n[Active Vulnerability Context]:\n"
                f"- Vuln Type: {finding_ctx.get('vuln_type')}\n"
                f"- Target Endpoint: {finding_ctx.get('method')} {finding_ctx.get('endpoint')}\n"
                f"- Severity: {finding_ctx.get('severity')} (CVSS {finding_ctx.get('cvss_score')})\n"
                f"- Evidence: {finding_ctx.get('evidence')}\n"
            )
        elif scan_summary:
            findings_str = ""
            if scan_summary.get("findings"):
                for idx, f in enumerate(scan_summary.get("findings")[:10]):
                    findings_str += f"\n  {idx+1}. {f.get('vuln_type')} on {f.get('endpoint')} ({f.get('severity')})"
            context_prompt = (
                f"\n[Scan Overview Context]:\n"
                f"- Total Findings: {scan_summary.get('findings_count')}\n"
                f"- Critical: {scan_summary.get('critical_count')}, High: {scan_summary.get('high_count')}\n"
                f"- Overall Risk Index: {scan_summary.get('overall_risk_score')}/100\n"
                f"- Discovered Vulnerabilities:{findings_str}\n"
            )

        full_prompt = f"{context_prompt}\nUser Query: {user_msg}\nProvide a clear, technical, and actionable response."

        # If Gemini API is available and configured
        if request.gemini_api_key:
            custom_ai = GeminiSecurityBrain(api_key=request.gemini_api_key)
            llm_reply = await custom_ai._call_gemini(full_prompt, system_prompt)
            if llm_reply:
                return ChatResponse(
                    reply=llm_reply,
                    suggested_actions=[
                        "Generate automatic GitHub PR fix",
                        "Show curl reproduction command",
                        "Explain CVSS 3.1 score metrics"
                    ],
                    auto_speak=auto_speak
                )

        # Built-in contextual cyber assistant fallback
        if "bola" in low_q or "idor" in low_q or "vehicle" in low_q:
            reply = (
                "**BOLA / IDOR (OWASP API1:2023) Explanation**:\n\n"
                "The vulnerability occurs because `/identity/api/v2/vehicle/{vehicle_id}/location` verifies that the caller has a *valid token*, but fails to verify if that token actually *owns* `vehicle_id`.\n\n"
                "**How to remediate in FastAPI**:\n"
                "```python\n"
                "@app.get('/vehicle/{vehicle_id}/location')\n"
                "def get_location(vehicle_id: str, current_user = Depends(get_current_user)):\n"
                "    item = db.query(Vehicle).filter_by(vehicle_id=vehicle_id, owner_id=current_user.id).first()\n"
                "    if not item:\n"
                "        raise HTTPException(status_code=404, detail='Not found') # Prevents ID enumeration\n"
                "    return item\n"
                "```\n"
                "Would you like me to generate a complete Pull Request patch for your repository?"
            )
            suggested = ["Generate PR Fix", "View Attack Graph Path", "Explain Impact to Management"]
        elif "bfla" in low_q or "admin" in low_q or "role" in low_q:
            reply = (
                "**BFLA (OWASP API5:2023) Explanation**:\n\n"
                "The endpoint `/admin/api/v1/users/{user_id}` allows regular `role='user'` accounts to invoke administrative functions like deletion without RBAC validation.\n\n"
                "**Remediation Recommendation**:\n"
                "Implement a role-check dependency:\n"
                "```python\n"
                "def require_admin(user: User = Depends(get_current_user)):\n"
                "    if user.role != 'admin':\n"
                "        raise HTTPException(status_code=403, detail='Administrative privileges required')\n"
                "    return user\n"
                "```"
            )
            suggested = ["Generate RBAC Middleware", "Check Misconfigurations"]
        elif "manager" in low_q or "business" in low_q or "executive" in low_q or "impact" in low_q:
            reply = (
                "**Executive Risk Summary for Stakeholders**:\n\n"
                "• **Regulatory Impact**: Cross-tenant data leakage directly violates GDPR Art. 32 and CCPA requirements, creating substantial mandatory breach notification liabilities.\n"
                "• **Exploitability**: The vulnerability requires zero prior credentials and can be automated via simple sequential identifier scripts.\n"
                "• **Immediate Action Required**: Apply tenant-level isolation middleware before next production deployment."
            )
            suggested = ["Download PDF Report", "Export Compliance Ledger"]
        elif "layman" in low_q or "simple" in low_q or "short" in low_q or "lay mans" in low_q:
            reply = (
                "**API Vulnerabilities in Ultra-Short Layman's Terms**:\n\n"
                "1. **BOLA / IDOR:** You have the key to your own house, but the lock is broken so your key accidentally opens your neighbor's house too. *(Seeing other people's private data).*\n"
                "2. **BFLA:** A normal customer walks behind the counter and opens the cash register because nobody stopped them. *(Regular users doing Admin actions).*\n"
                "3. **Excessive Data Exposure:** You ask for the time, and the person gives you their watch, their wallet, and their social security card. *(The system sends way too much hidden private info to the screen).*"
            )
            suggested = ["Explain technically", "How to fix BOLA?"]
        elif "fix" in low_q or "patch" in low_q or "pr" in low_q:
            reply = (
                "I can automatically package a Git Unified Diff patch for this finding. "
                "Click the **'Generate Fix PR'** button on the finding card, or let me know your target framework (FastAPI, Express, Spring Boot) to tailor the patch."
            )
            suggested = ["Generate Git Patch", "Run Regression Tests"]
        elif "vuln" in low_q or "vun" in low_q or "explain" in low_q or "find" in low_q or "result" in low_q:
            if scan_summary and scan_summary.get("findings"):
                reply = "**Here are the vulnerabilities found in the latest scan:**\n\n"
                for idx, f in enumerate(scan_summary.get("findings")[:5]):
                    reply += f"{idx+1}. **{f.get('vuln_type')}** at `{f.get('endpoint')}`\n"
                    reply += f"   *Impact*: {f.get('business_impact', 'Medium risk.')}\n"
                    if f.get('plain_english_summary'):
                        reply += f"   *Summary*: {f.get('plain_english_summary')}\n"
                    reply += "\n"
                reply += "Please let me know if you want a detailed patch for any of these."
            elif finding_ctx:
                reply = f"**Vulnerability Overview:** {finding_ctx.get('vuln_type')} at {finding_ctx.get('endpoint')}.\n"
                reply += f"*Impact*: {finding_ctx.get('business_impact', 'Medium risk.')}\n"
                reply += f"*Summary*: {finding_ctx.get('plain_english_summary', 'This endpoint requires authorization checks.')}"
            else:
                reply = "I don't have an active scan to explain. Please run a Zero-Trust scan first, or click 'Ask AI' on a specific finding."
            suggested = ["Generate Fix PR", "Download PDF Report"]
        else:
            reply = (
                f"I've analyzed your question regarding our Zero-Trust API audit. "
                f"In zero-trust architecture, every transaction must authenticate the actor and authorize the specific resource relationship (ReBAC). "
            )
            if scan_summary and scan_summary.get("findings"):
                reply += "\n\n**For your reference, here are the vulnerabilities we found:**\n"
                for idx, f in enumerate(scan_summary.get("findings")[:5]):
                    reply += f"{idx+1}. **{f.get('vuln_type')}** at `{f.get('endpoint')}`\n"
            else:
                reply += "\n\nHow can I help you resolve findings on your endpoints?"
            suggested = ["Why did IDOR happen?", "How to prevent schema drift?", "Generate Fix PR"]

        return ChatResponse(reply=reply, suggested_actions=suggested, auto_speak=auto_speak)
