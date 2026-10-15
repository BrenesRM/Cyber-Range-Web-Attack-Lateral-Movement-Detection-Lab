#!/usr/bin/env bash
# ==============================================================================
# CYBER RANGE AUTONOMOUS EMULATION & SOC DETECTION VALIDATION SCRIPT
# Executes MITRE ATT&CK mapped attacks and verifies Suricata IDS detection.
# ==============================================================================
set -e

COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

log_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"; }
log_step() { echo -e "${COLOR_YELLOW}[STEP]${COLOR_RESET} $1"; }
log_pass() { echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $1"; }
log_fail() { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $1"; }

TARGET_DMZ_IP="10.10.20.50"
TARGET_INTERNAL_IP="10.10.30.50"
CONTAINER_ATTACKER="cr-attacker-node"
CONTAINER_DMZ="cr-dmz-web"
CONTAINER_ROUTER="cr-edge-router-soc"

echo "========================================================================"
echo "    CYBER RANGE: WEB ATTACK & LATERAL MOVEMENT EMULATION RUNNER       "
echo "========================================================================"

# ------------------------------------------------------------------------------
# STEP 0: Health Check & Environment Verification
# ------------------------------------------------------------------------------
log_step "0. Verifying active Cyber Range containers..."
for c in "$CONTAINER_ATTACKER" "$CONTAINER_DMZ" "$CONTAINER_ROUTER" "cr-internal-corp"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        log_fail "Container $c is not running! Run 'docker compose up -d' first."
        exit 1
    fi
done
log_pass "All 4 Cyber Range containers are online."

# Clear previous logs for clean test
docker exec "$CONTAINER_ROUTER" truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
docker exec "$CONTAINER_ROUTER" truncate -s 0 /var/log/suricata/eve.json 2>/dev/null || true

# ------------------------------------------------------------------------------
# PHASE 1: RECONNAISSANCE (T1595 - Active Scanning)
# ------------------------------------------------------------------------------
log_step "1. Injecting Reconnaissance: External Nmap Port Scan against DMZ..."
docker exec "$CONTAINER_ATTACKER" nmap -sS -p 80,443,8080,3306 "$TARGET_DMZ_IP" -T4 > /dev/null 2>&1 || true
sleep 2

# ------------------------------------------------------------------------------
# PHASE 2: WEB EXPLOITATION (T1190 & T1083)
# ------------------------------------------------------------------------------
log_step "2. Injecting Web Exploitation Payloads (SQL Injection & Path Traversal)..."

# 2.1 SQL Injection: UNION SELECT
log_info "-> Executing SQL Injection (UNION SELECT)..."
docker exec "$CONTAINER_ATTACKER" curl -s -k "http://$TARGET_DMZ_IP/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,user()+--+&Submit=Submit" \
    -H "User-Agent: Mozilla/5.0 (Pentest Lab)" > /dev/null || true

# 2.2 SQL Injection: Automated Scanner Fingerprint
log_info "-> Executing SQL Injection with sqlmap signature..."
docker exec "$CONTAINER_ATTACKER" curl -s -k "http://$TARGET_DMZ_IP/vulnerabilities/sqli/?id=1'+or+1=1+--+" \
    -A "sqlmap/1.7#stable" > /dev/null || true

# 2.3 Directory Traversal / LFI
log_info "-> Executing LFI / Directory Traversal (/etc/passwd)..."
docker exec "$CONTAINER_ATTACKER" curl -s -k "http://$TARGET_DMZ_IP/vulnerabilities/fi/?page=../../../../etc/passwd" > /dev/null || true
sleep 3

# ------------------------------------------------------------------------------
# PHASE 3: PERIMETER BREACH ATTEMPT & LATERAL MOVEMENT (T1046, T1021)
# ------------------------------------------------------------------------------
log_step "3. Simulating Perimeter Breach & Lateral Movement..."

# 3.1 Direct External probe against Internal Corporate subnet (Must be blocked by Firewall)
log_info "-> Attempting direct external connection from Attacker to Internal DB ($TARGET_INTERNAL_IP)..."
docker exec "$CONTAINER_ATTACKER" nc -z -w 2 "$TARGET_INTERNAL_IP" 5000 > /dev/null 2>&1 || true

# 3.2 Pivoting from Compromised DMZ node to Internal Corporate API (Lateral Movement)
log_info "-> Compromised DMZ server pivoting laterally into Internal Corporate API (port 5000)..."
docker exec "$CONTAINER_DMZ" curl -s "http://$TARGET_INTERNAL_IP:5000/api/v1/customers" > /dev/null 2>&1 || \
    docker exec "$CONTAINER_DMZ" sh -c "echo 'GET /api/v1/customers HTTP/1.0\r\n\r\n' | nc $TARGET_INTERNAL_IP 5000" > /dev/null 2>&1 || true

sleep 3

# ------------------------------------------------------------------------------
# PHASE 4: SOC DETECTION & ALERT VALIDATION
# ------------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "                 PHASE 4: SOC SENSOR ALERT VALIDATION                   "
echo "========================================================================"

FAST_LOG=$(docker exec "$CONTAINER_ROUTER" cat /var/log/suricata/fast.log 2>/dev/null || echo "")

validate_detection() {
    local SID="$1"
    local DESCRIPTION="$2"
    if echo "$FAST_LOG" | grep -q "$SID"; then
        log_pass "DETECTED: [SID $SID] $DESCRIPTION"
        return 0
    else
        log_fail "MISSED:   [SID $SID] $DESCRIPTION"
        return 1
    fi
}

TESTS_PASSED=0
TOTAL_TESTS=5

# Check specific detections
validate_detection "1000002" "Automated Vulnerability Scanner (sqlmap)" && ((TESTS_PASSED++)) || true
validate_detection "1000010" "SQL Injection (UNION SELECT Pattern)" && ((TESTS_PASSED++)) || true
validate_detection "1000020" "Directory Traversal / LFI (/etc/passwd)" && ((TESTS_PASSED++)) || true
validate_detection "1000040" "Perimeter Violation (Direct External to Internal Probe)" && ((TESTS_PASSED++)) || true
validate_detection "1000030" "Lateral Movement (DMZ to Internal Network Activity)" && ((TESTS_PASSED++)) || true

echo ""
echo "------------------------------------------------------------------------"
echo "DETECTION SUMMARY: $TESTS_PASSED / $TOTAL_TESTS Tests Triggered Successfully."
echo "------------------------------------------------------------------------"

if [ "$TESTS_PASSED" -ge 4 ]; then
    echo -e "${COLOR_GREEN}[SUCCESS] Cyber Range attack emulation and detection validation passed!${COLOR_RESET}"
    echo ""
    echo "Sample Suricata Log Alerts Triggered:"
    echo "$FAST_LOG" | tail -n 10
    exit 0
else
    echo -e "${COLOR_RED}[WARNING] Some detection alerts were not registered in fast.log.${COLOR_RESET}"
    exit 1
fi
