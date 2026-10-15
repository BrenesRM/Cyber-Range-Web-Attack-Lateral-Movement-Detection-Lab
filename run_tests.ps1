# ==============================================================================
# CYBER RANGE AUTOMATED TEST RUNNER (PowerShell)
# ==============================================================================
[CmdletBinding()]
param(
    [switch]$VerboseOutput
)

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "             CYBER RANGE: AUTOMATED TEST SUITE RUNNER                   " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# Check Python availability
$pythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $pythonCmd) {
    Write-Host "[-] Python is not in PATH. Falling back to PowerShell-native test runner..." -ForegroundColor Yellow
    .\emulation_attack_and_detect.ps1
    exit $LASTEXITCODE
}

Write-Host "[+] Executing Python Comprehensive Unit & Integration Test Suite..." -ForegroundColor Green
$pyArgs = @("tests\test_cyber_range.py")
if ($VerboseOutput) {
    $pyArgs += "-v"
}

python @pyArgs
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "`n[SUCCESS] All Cyber Range tests passed successfully!" -ForegroundColor Green
} else {
    Write-Host "`n[FAILED] One or more tests in the Cyber Range suite failed." -ForegroundColor Red
}

exit $exitCode
