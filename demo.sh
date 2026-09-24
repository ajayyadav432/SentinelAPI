#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "🛡️  SentinelAPI — Zero-Trust API Vulnerability Scanner"
echo "    AmiHacks 2026 | Track C: Deep-Tech Industry Solution"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate Python virtual environment
if [ ! -d ".venv" ]; then
    echo "[!] Creating virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install fastapi uvicorn httpx pydantic pyyaml python-multipart websockets
else
    source .venv/bin/activate
fi

# Ensure frontend dependencies
if [ ! -d "frontend/node_modules" ]; then
    echo "[!] Installing frontend dependencies..."
    cd frontend && npm install && cd ..
fi

echo "[+] Starting SentinelAPI Backend on http://127.0.0.1:8000 ..."
export PYTHONPATH="$SCRIPT_DIR"
uvicorn backend.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

echo "[+] Starting SentinelAPI Frontend on http://127.0.0.1:5180 ..."
cd frontend
npm run dev -- --host 127.0.0.1 --port 5180 &
FRONTEND_PID=$!
cd ..

cleanup() {
    echo ""
    echo "[*] Shutting down SentinelAPI services..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "[✓] Shutdown clean."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "=========================================================="
echo "🚀 SentinelAPI is LIVE and READY FOR JUDGES!"
echo "   Dashboard UI : http://127.0.0.1:5180"
echo "   Backend API  : http://127.0.0.1:8000"
echo "   Target API   : http://127.0.0.1:8000/sandbox-target"
echo "=========================================================="
echo "Press Ctrl+C to terminate services."

wait
