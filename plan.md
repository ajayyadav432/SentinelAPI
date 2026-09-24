# 🛡️ SentinelAPI — Hackathon Winning Plan
### AmiHacks 2026 | Track C: Zero-Trust API Vulnerability Scanner | 24 Hours

---

> **Tagline:** *"Find the API vulnerability before the breach headline does."*

---

## 📌 Executive Summary

We are building **SentinelAPI** — an AI-augmented, zero-trust API vulnerability scanner that:
1. Ingests an **OpenAPI/Swagger spec** or **live traffic** (HAR file / proxy capture)
2. Uses **Gemini 2.0 Flash** (LLM) to reason about authorization logic and generate smart attack test cases
3. Automatically discovers **IDOR, excessive data exposure, auth misconfigs, rate-limit bypass**
4. Produces **severity-ranked, actionable findings** with reproducible PoC curl commands
5. Presents findings in a **premium real-time dashboard** with risk scores, fix suggestions, and audit trail

**What makes us WIN:** We combine traditional fuzzing with LLM-powered reasoning — something no open-source tool currently does well. Judges will see a working demo against a real vulnerable API (crAPI) in under 60 seconds.

---

## 🏆 Why This Will Win

| Winning Factor | Our Approach |
|---|---|
| **Technical depth** | LLM agent chains multi-step exploits; graph-based endpoint mapping |
| **Wow factor** | Real-time attack playback in dashboard; AI explains each vuln in plain English |
| **Completeness** | End-to-end: ingest → scan → report → fix suggestion |
| **Judging criteria hit** | Innovation (AI), Practical impact, Scalability, Clean UX |
| **Demo-able in 2 min** | One command → full vuln report against crAPI sandbox |

---

## 🗺️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SentinelAPI                              │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────────┐    │
│  │  Ingest  │───▶│  AI Planner  │───▶│  Attack Engine     │    │
│  │ (Spec /  │    │ (Gemini 2.0  │    │ (HTTP Fuzzer +     │    │
│  │  Traffic)│    │  Flash)      │    │  Auth Swapper)     │    │
│  └──────────┘    └──────────────┘    └────────────────────┘    │
│                                              │                  │
│                                              ▼                  │
│                        ┌──────────────────────────────┐        │
│                        │   Vulnerability Classifier   │        │
│                        │  (OWASP API Top 10 engine)   │        │
│                        └──────────────────────────────┘        │
│                                              │                  │
│                                              ▼                  │
│                        ┌──────────────────────────────┐        │
│                        │      Report Generator        │        │
│                        │  (Severity + PoC + Fix)      │        │
│                        └──────────────────────────────┘        │
│                                              │                  │
│                                              ▼                  │
│                        ┌──────────────────────────────┐        │
│                        │    Premium Dashboard (UI)    │        │
│                        │   React + Real-time WebSocket│        │
│                        └──────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Vulnerability Classes We Will Detect (Priority Order)

### 🔴 P1 — Must Have (MVP Core)
1. **IDOR / Broken Object-Level Authorization (BOLA)** — API1:2023
   - Swap numeric/UUID identifiers across two authenticated sessions
   - e.g., `/orders/123` accessed with User B's token while User A owns it
   
2. **Broken Function-Level Authorization (BFLA)** — API5:2023
   - Test admin endpoints with regular-user tokens
   - e.g., `DELETE /admin/users/{id}` called as non-admin

3. **Excessive Data Exposure** — API3:2023
   - Compare response fields against what spec says should be returned
   - Flag responses with `password`, `token`, `ssn`, `private_key` patterns

### 🟡 P2 — Should Have (Strong Demo Value)
4. **Missing/Weak Rate Limiting** — API4:2023
   - Hammer endpoints 50x in 5 seconds, detect no 429 response
   
5. **Security Misconfiguration** — API8:2023
   - Missing CORS headers, HTTPS downgrade, verbose error messages leaking stack traces

### 🟢 P3 — Advanced / Bonus
6. **Mass Assignment** — API6:2023
   - Send extra fields in POST body and check if server accepts them
   
7. **Multi-step Agentic Exploit Chain**
   - LLM discovers: register → get token → use token to access another user's data

---

## 🧠 AI/LLM Strategy (The Secret Weapon)

### How We Use Gemini 2.0 Flash

**Step 1 — Spec Analysis (AI reads the spec like a senior pentester):**
```
Prompt: "You are a security researcher. Given this OpenAPI spec, identify:
1. All endpoints that take user-controlled IDs in path/query params
2. Endpoints that should have different access levels (admin vs user)  
3. Response schemas that might expose sensitive fields
4. Business logic patterns that suggest authorization dependencies
Output as structured JSON."
```

**Step 2 — Smart Test Case Generation:**
```
Prompt: "For endpoint GET /api/orders/{orderId}, generate 10 IDOR test scenarios:
- What IDs to try (sequential, UUID-guessing, negative numbers, 0)
- Which HTTP headers to manipulate
- What to compare in the response to confirm exploitation
Output as executable test cases."
```

**Step 3 — Finding Explanation (AI explains vulns in plain English):**
```
Prompt: "Explain this vulnerability to a non-security engineer:
Finding: User B's token successfully retrieved User A's order data from GET /orders/42
Severity: Critical
Write: (1) What happened, (2) Why it's dangerous, (3) How to fix it in 3 bullet points."
```

**Step 4 — Agentic Multi-Step Exploitation (Advanced):**
- AI plans a multi-step attack chain: auth → discover IDs → exploit → confirm data leak
- Uses tool-calling: `make_request()`, `store_token()`, `compare_responses()`

---

## 🏗️ Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **Backend** | Python 3.12 + FastAPI | Fast async HTTP, clean API |
| **AI** | Google Gemini 2.0 Flash (gemini-2.0-flash) | Reasoning + structured output |
| **HTTP Engine** | `httpx` (async) | Concurrent attack requests |
| **Spec Parser** | `openapi-spec-validator` + `prance` | Handle $ref resolution |
| **Frontend** | React + Vite + Recharts | Premium real-time dashboard |
| **WebSocket** | FastAPI WebSocket | Live scan progress streaming |
| **Target (Demo)** | crAPI (Completely Ridiculous API) | Docker-based, realistic vulns |
| **Report** | PDF via `weasyprint` | Downloadable pentest report |
| **CI Demo** | GitHub Actions + YAML | Optional: show CI integration |

---

## 📁 Project Structure

```
sentinelapi/
├── backend/
│   ├── main.py                  # FastAPI app + WebSocket
│   ├── ingestion/
│   │   ├── spec_parser.py       # OpenAPI spec loader
│   │   └── traffic_parser.py   # HAR file parser
│   ├── ai/
│   │   ├── planner.py           # Gemini: spec analysis + test planning
│   │   ├── explainer.py         # Gemini: finding explanation
│   │   └── agent.py             # Agentic multi-step exploit chain
│   ├── scanners/
│   │   ├── idor_scanner.py      # IDOR/BOLA detection
│   │   ├── bfla_scanner.py      # Broken function-level auth
│   │   ├── data_exposure.py     # Excessive data exposure
│   │   ├── rate_limit.py        # Rate limiting checks
│   │   └── misconfig.py         # Security misconfigurations
│   ├── engine/
│   │   ├── http_client.py       # Async HTTP engine
│   │   ├── session_manager.py   # Multi-user session handling
│   │   └── scheduler.py         # Concurrent scan orchestration
│   ├── reporting/
│   │   ├── classifier.py        # CVSS scoring + severity rating
│   │   ├── report_gen.py        # PDF + JSON report generation
│   │   └── poc_builder.py       # Reproducible curl command builder
│   └── sandbox/
│       └── docker-compose.yml   # crAPI vulnerable target
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── Dashboard.jsx    # Main scan view
│   │   │   ├── FindingCard.jsx  # Per-finding display
│   │   │   ├── ScanProgress.jsx # Real-time WebSocket progress
│   │   │   ├── RiskChart.jsx    # CVSS severity chart
│   │   │   └── PoCViewer.jsx    # Curl command viewer
│   │   └── index.css
│   └── package.json
├── tests/
│   └── test_scanners.py
├── README.md
├── demo.sh                      # One-command demo script
└── plan.md                      # This file
```

---

## ⏱️ 24-Hour Timeline (Hour-by-Hour)

### Phase 1: Foundation (Hours 0-4)
| Time | Task | Owner |
|------|------|-------|
| H0-1 | Setup: repo, Docker (crAPI target), Python venv, Gemini API key | All |
| H1-2 | `spec_parser.py`: load OpenAPI spec, extract all endpoints + schemas | Dev 1 |
| H1-2 | `http_client.py`: async HTTP engine with session management | Dev 2 |
| H2-3 | `planner.py`: Gemini prompt to analyze spec and identify risky endpoints | Dev 1 |
| H2-3 | `session_manager.py`: two-user session setup for IDOR testing | Dev 2 |
| H3-4 | Vite + React project scaffold, install deps, basic routing | Dev 3/4 |

**Phase 1 Exit Criteria:** Can load an OpenAPI spec, Gemini returns a structured analysis JSON, two HTTP sessions exist.

---

### Phase 2: Core Scanners (Hours 4-12)
| Time | Task | Owner |
|------|------|-------|
| H4-6 | `idor_scanner.py`: enumerate IDs, swap tokens, compare responses | Dev 1 |
| H4-6 | `data_exposure.py`: regex + schema-diff for sensitive field leakage | Dev 2 |
| H6-8 | `bfla_scanner.py`: test admin endpoints with low-priv tokens | Dev 1 |
| H6-8 | `rate_limit.py`: concurrent burst testing, 429 detection | Dev 2 |
| H8-10 | `classifier.py`: CVSS v3 severity scoring, OWASP mapping | Dev 1 |
| H8-10 | `poc_builder.py`: generate reproducible curl commands per finding | Dev 2 |
| H10-12 | `explainer.py`: Gemini explains each finding in plain English + fix advice | Dev 1 |
| H10-12 | FastAPI endpoints: `/scan`, `/status`, `/findings`, WebSocket `/ws/progress` | Dev 2 |

**Phase 2 Exit Criteria:** Running scanner detects at least 2 real vulns in crAPI, generates PoC curl, has severity scores.

---

### Phase 3: UI + Polish (Hours 12-18)
| Time | Task | Owner |
|------|------|-------|
| H12-14 | `Dashboard.jsx`: scan config form, scan launch, WebSocket progress bar | Dev 3 |
| H12-14 | `FindingCard.jsx`: severity badge, description, PoC view, fix advice | Dev 4 |
| H14-16 | `RiskChart.jsx`: donut chart of vulns by severity | Dev 3 |
| H14-16 | `ScanProgress.jsx`: real-time live feed of requests being tested | Dev 4 |
| H16-18 | Full CSS polish: dark mode, glassmorphism, premium feel | Dev 3/4 |
| H16-18 | PDF report generation with `weasyprint` | Dev 2 |

**Phase 3 Exit Criteria:** Full end-to-end flow works in browser: upload spec → scan runs → findings appear live → downloadable report.

---

### Phase 4: Advanced Features + Demo Prep (Hours 18-22)
| Time | Task | Owner |
|------|------|-------|
| H18-20 | `agent.py`: agentic multi-step exploit chain using Gemini tool-calling | Dev 1 |
| H18-20 | `misconfig.py`: CORS, TLS, verbose errors scanner | Dev 2 |
| H20-22 | `demo.sh`: one-command full demo (docker up → scan → open browser) | All |
| H20-22 | README.md: architecture, setup, usage, screenshots | Dev 4 |
| H20-22 | Stress test with a 100-endpoint spec; fix crash edge cases | Dev 1+2 |

**Phase 4 Exit Criteria:** Agentic chain discovers a multi-step exploit. Demo script runs clean in < 90 seconds.

---

### Phase 5: Buffer + Presentation (Hours 22-24)
| Time | Task | Owner |
|------|------|-------|
| H22-23 | Bug fixes, performance tuning, edge case hardening | Dev 1+2 |
| H22-23 | Presentation slides: problem, solution, demo, architecture, impact | Dev 3+4 |
| H23-24 | Final demo rehearsal: 5 min pitch + 2 min demo run | All |

---

## 🎯 Demo Script (What Judges Will See)

**Setup (hidden, pre-done):**
```bash
./demo.sh  # Starts crAPI docker, backend, frontend in one command
```

**Live Demo Flow (2 minutes):**
1. Open browser → SentinelAPI dashboard (glassmorphism dark UI)
2. Upload `crapi-openapi.yaml` → click **"Start Scan"**
3. Watch real-time feed: "Testing GET /community/posts/{id}... 🔴 IDOR Found!"
4. Click finding → AI explanation appears: *"User B's token accessed User A's vehicle data..."*
5. Show PoC tab: copy-paste curl command that reproduces the exploit
6. Show Fix tab: *"Add authorization check: verify request.user.id == object.owner_id"*
7. Show Risk Overview donut chart: 3 Critical, 5 High, 2 Medium
8. Click Download Report → PDF pentest report downloads
9. **Optional**: Show agentic chain tab — AI discovered a 3-step exploit chain

---

## 📊 Scoring Criteria Alignment

| Judging Axis | How We Win |
|---|---|
| **Innovation** | LLM-powered authorization reasoning; agentic multi-step exploit chains |
| **Technical Complexity** | Async concurrent scanning, AI tool-calling agent, real-time WebSocket UI |
| **Impact** | Solves real problem; targets underserved SMB/startup security teams |
| **Completeness** | End-to-end: ingest → AI analysis → scan → findings → PoC → fix → report |
| **Presentation** | Premium glassmorphism dashboard; one-command reproducible demo; PDF report |

---

## 🚨 Risk Register & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Gemini API rate limit during demo | Medium | Cache all AI responses; use gemini-2.0-flash (faster + cheaper) |
| crAPI docker fails to start | Low | Have backup: pre-recorded scan results JSON, offline demo mode |
| IDOR scanner produces false positives | Medium | Only flag when response bodies contain user-specific fields AND match across sessions |
| UI not ready in time | Medium | MVP: simple HTML/JS fallback; JSON API output is itself demonstrable |
| Team member sick/absent | Low | All code in shared repo with clear module boundaries |

---

## 🔑 Key Technical Decisions

### Why crAPI (not DVWA)?
crAPI (Completely Ridiculous API) is purpose-built to demo API-specific vulns like IDOR, BFLA, and mass assignment. DVWA tests web app vulns, not API vulns. Judges who know their stuff will notice.

### Why Gemini 2.0 Flash?
- Structured output (JSON mode) — no parsing hacks
- Function/tool calling — enables the agentic chain
- Fast enough for real-time scan augmentation
- Free tier sufficient for a 24-hr hackathon

### Why Async Python (httpx + FastAPI)?
Scanning 100 endpoints with 10 token permutations each = 1000 HTTP requests. Async cuts this from ~100s (sync) to ~5s (async concurrent). Speed matters in demos.

### Why Not Just Use ZAP/Burp?
Because we're adding what none of them have: **LLM-powered authorization reasoning**. Our differentiator is AI understanding *intent* (what the API is supposed to allow), not just pattern-matching traffic.

---

## 🔧 Environment Setup (Day-of Checklist)

```bash
# Prerequisites
# - Python 3.12+, Node 20+, Docker + Docker Compose, GEMINI_API_KEY

# Start vulnerable target
cd backend/sandbox && docker-compose up -d  # crAPI on :8888

# Start backend
cd backend
pip install -r requirements.txt
GEMINI_API_KEY=your_key uvicorn main:app --reload --port 8000

# Start frontend
cd frontend
npm install && npm run dev  # starts on :5173
```

---

## 📦 Core Dependencies

**Backend:**
```
fastapi, uvicorn, httpx, google-generativeai, openapi-spec-validator, prance, weasyprint, pydantic, websockets
```

**Frontend:**
```
react, react-dom, recharts, axios, lucide-react, vite
```

---

## 🎨 UI Design Direction

**Theme:** Dark glassmorphism + electric blue/red accent
- Background: `#0a0a0f` with subtle gradient
- Cards: `rgba(255,255,255,0.05)` with `backdrop-filter: blur(12px)`
- Critical findings: Red glow effect | High: Orange | Medium/Low: Yellow/Blue
- Real-time scan log: Matrix-style scrolling feed
- Severity donut chart: Animated on load

**4 Pages:**
1. **Home / Upload** — drag & drop OpenAPI spec or paste URL
2. **Scan Dashboard** — live progress feed + findings as they appear
3. **Findings Detail** — per-vulnerability deep dive with AI explanation + PoC + fix
4. **Report** — downloadable PDF + JSON export

---

## 🔌 API Contract (Backend ↔ Frontend)

```
POST /api/scan
  Body: { spec_url | spec_file, target_base_url, user_tokens: [token_a, token_b] }
  Returns: { scan_id: "uuid" }

GET /api/scan/{scan_id}/status
  Returns: { status, progress_pct, endpoints_tested, findings_count }

GET /api/scan/{scan_id}/findings
  Returns: [{ id, vuln_class, severity, endpoint, description, poc_curl, fix_advice, cvss_score }]

WebSocket /ws/scan/{scan_id}
  Server pushes: { type: "progress"|"finding"|"complete", data: {...} }

GET /api/scan/{scan_id}/report.pdf   → PDF binary
GET /api/scan/{scan_id}/report.json  → Full JSON report
```

---

## 🌟 Stretch Goals (If Time Permits)

- [ ] GitHub Actions YAML showing CI/CD integration
- [ ] Mass Assignment scanner (extra fields in POST body)
- [ ] GraphQL support via introspection
- [ ] CLI mode: `sentinel scan --spec api.yaml --tokens user.json`
- [ ] Vuln trend dashboard across scan history

---

## 🤝 Team Roles

| Role | Focus |
|---|---|
| **Dev 1** | Python backend: IDOR scanner, AI planner, agentic chain |
| **Dev 2** | Python backend: HTTP engine, other scanners, report generation |
| **Dev 3** | Frontend: Dashboard UI, real-time WebSocket, charts |
| **Dev 4** | Frontend: Finding detail views, CSS polish, README, slides |

> **2-person team:** Dev 1 owns all backend; Dev 2 owns frontend + presentation. MVP focus: IDOR scanner + data exposure + working UI.

---

## 🏁 Definition of Done (MVP = Guaranteed Demo-able)

- [ ] crAPI docker starts from `docker-compose up`
- [ ] Upload `crapi-openapi.yaml` in UI → scan launches
- [ ] Scan detects at least **2 findings** (IDOR + excessive data exposure)
- [ ] Each finding shows: severity, description, AI explanation, PoC curl, fix advice
- [ ] Real-time WebSocket progress visible in UI
- [ ] Download button produces a PDF report
- [ ] Demo runs cleanly in < 3 minutes

---

*Built for AmiHacks 2026 · Track C: Industry / Deep-Tech · Duration: 24 Hours*
