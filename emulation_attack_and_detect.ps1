# ==============================================================================
# CYBER RANGE AUTONOMOUS ATTACK & SOC DETECTION VALIDATION (PowerShell)
# ==============================================================================
[CmdletBinding()]
param()

$TargetDmzIp = "10.10.20.50"
$TargetInternalIp = "10.10.30.50"
$ContainerAttacker = "cr-attacker-node"
$ContainerDmz = "cr-dmz-web"
$ContainerRouter = "cr-edge-router-soc"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "    CYBER RANGE: WEB ATTACK & LATERAL MOVEMENT EMULATION RUNNER       " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 0. Health check
Write-Host "[STEP 0] Checking running containers..." -ForegroundColor Yellow
$containers = @($ContainerAttacker, $ContainerDmz, $ContainerRouter, "cr-internal-corp")
foreach ($c in $containers) {
    $exists = docker ps --filter "name=$c" --format "{{.Names}}"
    if (-not $exists) {
        Write-Host "[-] Container $c is NOT running. Run 'docker compose up -d' first." -ForegroundColor Red
        exit 1
    }
}
Write-Host "[+] All Cyber Range containers are UP." -ForegroundColor Green

# Reset logs
docker exec $ContainerRouter truncate -s 0 /var/log/suricata/fast.log 2>$null

# 1. Reconnaissance
Write-Host "`n[STEP 1] Injecting External Nmap Port Scan..." -ForegroundColor Yellow
docker exec $ContainerAttacker nmap -sS -p 80,443,8080,3306 $TargetDmzIp -T4 *>$null
Start-Sleep -Seconds 2

# 2. Web Exploitation
Write-Host "[STEP 2] Injecting SQLi and LFI Payloads..." -ForegroundColor Yellow
Write-Host " -> SQLi UNION SELECT..."
docker exec $ContainerAttacker curl -s -k "http://$TargetDmzIp/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,user()+--+&Submit=Submit" -H "User-Agent: Mozilla/5.0" *>$null

Write-Host " -> SQLi sqlmap scanner signature..."
docker exec $ContainerAttacker curl -s -k "http://$TargetDmzIp/vulnerabilities/sqli/?id=1'+or+1=1+--+" -A "sqlmap/1.7#stable" *>$null

Write-Host " -> LFI /etc/passwd traversal..."
docker exec $ContainerAttacker curl -s -k "http://$TargetDmzIp/vulnerabilities/fi/?page=../../../../etc/passwd" *>$null
Start-Sleep -Seconds 3

# 3. Perimeter Breach & Lateral Movement
Write-Host "[STEP 3] Testing Perimeter Breach & Lateral Movement..." -ForegroundColor Yellow
Write-Host " -> Direct external probe to Internal DB (10.10.30.50:5000)..."
docker exec $ContainerAttacker nc -z -w 2 $TargetInternalIp 5000 *>$null

Write-Host " -> Pivoting from DMZ to Internal API (10.10.30.50:5000)..."
docker exec $ContainerDmz curl -s "http://${TargetInternalIp}:5000/api/v1/customers" *>$null
Start-Sleep -Seconds 3

# 4. Validation
Write-Host "`n========================================================================" -ForegroundColor Cyan
Write-Host "                 PHASE 4: SOC ALERT VALIDATION                          " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

$fastLog = docker exec $ContainerRouter cat /var/log/suricata/fast.log 2>$null

$tests = @(
    @{ Sid = "1000002"; Desc = "Automated Vulnerability Scanner (sqlmap)" },
    @{ Sid = "1000010"; Desc = "SQL Injection (UNION SELECT Pattern)" },
    @{ Sid = "1000020"; Desc = "Directory Traversal / LFI (/etc/passwd)" },
    @{ Sid = "1000040"; Desc = "Perimeter Violation (Direct External Probe)" },
    @{ Sid = "1000030"; Desc = "Lateral Movement (DMZ to Internal Pivot)" }
)

$passed = 0
foreach ($t in $tests) {
    if ($fastLog -match $t.Sid) {
        Write-Host "[PASS] DETECTED: [SID $($t.Sid)] $($t.Desc)" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "[FAIL] MISSED:   [SID $($t.Sid)] $($t.Desc)" -ForegroundColor Red
    }
}

Write-Host "`n------------------------------------------------------------------------"
Write-Host "DETECTION SUMMARY: $passed / $($tests.Count) detections verified."
Write-Host "------------------------------------------------------------------------"

if ($passed -ge 4) {
    Write-Host "[SUCCESS] Cyber Range attack emulation completed successfully!" -ForegroundColor Green
} else {
    Write-Host "[WARNING] One or more alerts were not captured." -ForegroundColor Yellow
}
