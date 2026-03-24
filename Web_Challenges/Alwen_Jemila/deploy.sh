#!/bin/bash
# Deploy ChromaLeak to VPS
# Run this ON the VPS after copying files

set -e

echo "[*] Installing Docker (if needed)..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "[!] Docker installed. You may need to log out and back in for group changes."
    echo "[!] Then re-run this script."
    exit 0
fi

echo "[*] Starting ChromaLeak on port 4002..."
cd ~/chromaleak
docker compose down 2>/dev/null || true
docker compose up --build -d

echo ""
echo "[*] Waiting for container to start..."
sleep 5

echo "[*] Container status:"
docker ps --filter "name=chromaleak" --format "{{.Names}} {{.Status}}"

echo ""
echo "[*] Testing..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4002/ 2>/dev/null || echo "fail")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] ChromaLeak is UP at http://20.199.128.9:4002"
else
    echo "[!] Not responding yet. Check: docker logs chromaleak-chromaleak-1"
fi

echo ""
echo "[*] Logs:"
docker compose logs --tail 10
