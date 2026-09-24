# 🛡️ SentinelAPI — Zero-Trust API Vulnerability Scanner
### *Find the API vulnerability before the breach headline does.*

[![CI](https://github.com/ajayyadav432/SentinelAPI/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayyadav432/SentinelAPI/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%20(2023)-red.svg)](https://owasp.org/www-project-api-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **AmiHacks 2026** | **Track C: Industry / Deep-Tech** | Zero-Trust Tooling

---

## 🚀 Overview

Modern applications expose hundreds of internal and third-party APIs. While generic web scanners catch superficial issues (missing headers, outdated TLS), they completely miss **logic-level authorization flaws** like **Broken Object Level Authorization (BOLA/IDOR)** and **Broken Function Level Authorization (BFLA)** — where syntactically valid requests leak another customer's private data.

**SentinelAPI** is an AI-augmented, zero-trust API vulnerability scanner that:
1. **Ingests API Definitions & Traffic**: Ingests OpenAPI 3.x / Swagger 2.0 specs or live HTTP Archive (HAR) traffic captures.
2. **AI Authorization Reasoning**: Uses **Google Gemini 2.0 Flash** to reason about resource boundaries, parameter hierarchies, and administrative roles.
3. **Deterministic Fuzzing & Token Swapping**: Automatically executes cross-tenant token swapping (User A vs User B vs Anonymous) to verify authorization boundaries without false positives.
4. **Autonomous Pentest Agent**: Chains multi-step exploits (Reconnaissance → Harvesting Victim IDs → BOLA Exploitation → Data Exfiltration).
5. **Real-time Glassmorphism Dashboard**: Streams live audit progress, CVSS scoring, reproducible `cURL` PoCs, and developer code fixes.
6. **Executive Audit Reports**: Generates downloadable executive HTML and JSON penetration testing reports.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                             SentinelAPI                                │
│                                                                        │
│   ┌────────────────────┐    ┌──────────────────────────────────────┐   │
│   │ Ingestion Engine   │───▶│ AI Security Brain (Gemini 2.0 Flash) │   │
│   │ (OpenAPI 3.x / HAR)│    │ - Spec topology analysis             │   │
│   └────────────────────┘    │ - Adaptive fuzzing heuristics        │   │
│             │               │ - Plain-English developer fixes      │   │
│             ▼               └──────────────────────────────────────┘   │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ Attack Engine (Async HTTP Client + Dual-Session Manager)       │   │
│   │                                                                │   │
│   │ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │   │
│   │ │ IDOR / BOLA  │ │ BFLA Scanner │ │ Excessive Data Exposure  │ │   │
│   │ │ (API1:2023)  │ │ (API5:2023)  │ │ (API3:2023)              │ │   │
│   │ └──────────────┘ └──────────────┘ └──────────────────────────┘ │   │
│   │ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │   │
│   │ │ Rate Limiter │ │ Misconfig    │ │ Autonomous Pentest Agent │ │   │
│   │ │ (API4:2023)  │ │ (API8:2023)  │ │ (Multi-Step Exploit)     │ │   │
│   │ └──────────────┘ └──────────────┘ └──────────────────────────┘ │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                     │                                  │
│                                     ▼                                  │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ Real-Time Dashboard (React + WebSocket + Glassmorphic UI)      │   │
│   │ - Live radar execution console - CVSS v3.1 Risk Score          │   │
│   │ - Reproducible cURL PoC viewer - Downloadable HTML Audit Report│   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 OWASP API Security Top 10 Coverage

| OWASP Tag | Vulnerability Class | SentinelAPI Detection Strategy | Severity |
|---|---|---|---|
| **API1:2023** | **BOLA / IDOR** | Dual-session token swapping (Attacker token vs Victim resource ID) | `CRITICAL` |
| **API2:2023** | **Broken Authentication** | Strips authentication headers to test anonymous access to private objects | `HIGH` |
| **API3:2023** | **Excessive Data Exposure** | Regex and pattern matching for leaked password hashes, JWTs, PII, and keys | `CRITICAL` |
| **API4:2023** | **Unrestricted Resource Use** | High-concurrency burst fuzzing (20+ reqs/sec) without 429 throttling | `HIGH` |
| **API5:2023** | **BFLA (Privilege Escalation)** | Tests administrative/privileged endpoints with standard user tokens | `CRITICAL` |
| **API8:2023** | **Security Misconfiguration** | Detects wildcard CORS with credentials, missing security headers | `HIGH` |

---

## ⚡ Quickstart (2-Minute Demo)

### Prerequisites
- Python 3.12+
- Node.js 20+

### One-Command Launch
```bash
git clone https://github.com/ajayyadav432/SentinelAPI.git
cd SentinelAPI
./demo.sh
```

- **Dashboard UI**: [http://127.0.0.1:5180](http://127.0.0.1:5180)
- **Scanner API**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Built-in Target Sandbox**: [http://127.0.0.1:8000/sandbox-target](http://127.0.0.1:8000/sandbox-target)

*(Optional: Set `export GEMINI_API_KEY=AIzaSy...` in your shell or enter it directly in the UI dashboard).*

---

## 🤖 Autonomous Pentest Agent (Chained Exploits)

SentinelAPI does not simply fuzz endpoints in isolation. It includes an **Autonomous Pentest Agent** that chains multiple API calls:
1. **Reconnaissance**: Accesses public feeds (`GET /community/posts`) to discover active customer entity identifiers.
2. **Correlation**: Identifies related private endpoints (`GET /identity/api/v2/vehicle/{id}/location`).
3. **Exploitation**: Employs an Attacker persona token to access the harvested Victim identifier.
4. **Exfiltration Confirmation**: Extracts sensitive GPS coordinates and telemetry, documenting the full exploit chain.

---

## 📊 Developer Remediation & PoC Viewer

Every finding discovered by SentinelAPI includes:
- **Reproducible cURL Command**: 1-click copyable proof-of-concept curl command.
- **AI Plain-English Summary**: Executive explanation of what happened and why it matters.
- **Business Impact**: Quantified financial and regulatory risk (GDPR, CCPA).
- **Defense-in-Depth Code Fix**: Copy-pasteable code fixes for FastAPI, Express, or Spring Boot.

---

## 🛠️ Testing & Quality Gate

SentinelAPI adheres to strict code-quality gates and test automation:
```bash
# Run pytest test suite
source .venv/bin/activate
pytest tests/test_full_suite.py -v

# Run SWE-loop objective quality metrics
python3 /home/ajay/.gemini/config/skills/swe-loop/tools/quality_check.py backend/**/*.py
```

---

## 👥 Hackathon Submission

- **Event**: AmiHacks 2026
- **Track**: Track C: Industry / Deep-Tech
- **Project**: SentinelAPI — Zero-Trust API Vulnerability Scanner
- **Author**: Ajay Yadav ([@ajayyadav432](https://github.com/ajayyadav432))

*Licensed under the [MIT License](LICENSE).*
