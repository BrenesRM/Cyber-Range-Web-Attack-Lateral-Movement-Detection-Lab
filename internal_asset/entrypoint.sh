#!/bin/sh
set -e

# Set default route to edge router
ip route del default 2>/dev/null || true
ip route add default via 10.10.30.1

echo "[+] Internal asset ready. Default gateway set to 10.10.30.1"

# Launch internal server
exec python3 /app/internal_server.py
