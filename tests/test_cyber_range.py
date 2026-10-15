#!/usr/bin/env python3
"""
================================================================================
CYBER RANGE COMPREHENSIVE TEST SUITE
Test categories:
  1. Infrastructure & Health (Containers, Suricata Process)
  2. Network Segmentation & Firewall Isolation Policies
  3. Attack Vector Emulation & IDS Detection Signatures (MITRE ATT&CK)
  4. Blue Team Telemetry & JSON-L Log Integrity
================================================================================
"""

import subprocess
import time
import json
import unittest
import sys

TARGET_DMZ_IP = "10.10.20.50"
TARGET_INTERNAL_IP = "10.10.30.50"
CONTAINER_ATTACKER = "cr-attacker-node"
CONTAINER_DMZ = "cr-dmz-web"
CONTAINER_ROUTER = "cr-edge-router-soc"
CONTAINER_INTERNAL = "cr-internal-corp"


def run_docker_exec(container, cmd, timeout=15):
    """Executes a command inside a docker container and returns (code, stdout, stderr)."""
    full_cmd = ["docker", "exec", container] + (cmd if isinstance(cmd, list) else cmd.split())
    try:
        res = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def get_suricata_fast_log():
    """Retrieves current content of fast.log from the router."""
    _, stdout, _ = run_docker_exec(CONTAINER_ROUTER, ["cat", "/var/log/suricata/fast.log"])
    return stdout


def get_suricata_eve_json():
    """Retrieves current eve.json lines from the router."""
    _, stdout, _ = run_docker_exec(CONTAINER_ROUTER, ["cat", "/var/log/suricata/eve.json"])
    lines = []
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            try:
                lines.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return lines


class TestCyberRangeLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n=======================================================")
        print("  INITIALIZING CYBER RANGE TEST SUITE")
        print("=======================================================")
        # Ensure DMZ web node has route to internal segment via router
        run_docker_exec(CONTAINER_DMZ, ["ip", "route", "add", "10.10.30.0/24", "via", "10.10.20.1"])
        
        # Ensure Suricata is active with PCAP multi-interface mode
        code, stdout, _ = run_docker_exec(CONTAINER_ROUTER, ["pgrep", "-f", "suricata"])
        if code != 0:
            run_docker_exec(CONTAINER_ROUTER, [
                "sh", "-c", "rm -f /var/run/suricata.pid; suricata -c /etc/suricata/suricata.yaml -k none --pcap -D"
            ])
            time.sleep(2)

    # --------------------------------------------------------------------------
    # CATEGORY 1: INFRASTRUCTURE & HEALTH
    # --------------------------------------------------------------------------
    def test_01_containers_running(self):
        """TC1.1: Verify all 4 lab containers are running."""
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            text=True
        )
        running = res.stdout.splitlines()
        for c in [CONTAINER_ROUTER, CONTAINER_ATTACKER, CONTAINER_DMZ, CONTAINER_INTERNAL]:
            self.assertIn(c, running, f"Container {c} is not active in 'docker ps'")
        print("  [+] TC1.1 PASSED: All 4 Cyber Range containers are running.")

    def test_02_suricata_process_alive(self):
        """TC1.2: Verify Suricata IDS process is active on edge router."""
        code, stdout, _ = run_docker_exec(CONTAINER_ROUTER, ["pgrep", "-f", "suricata"])
        self.assertEqual(code, 0, "Suricata process is not running on cr-edge-router-soc")
        print("  [+] TC1.2 PASSED: Suricata IDS daemon is active and running.")

    def test_03_router_ip_forwarding_enabled(self):
        """TC1.3: Verify IP forwarding is enabled in router kernel."""
        code, stdout, _ = run_docker_exec(CONTAINER_ROUTER, ["cat", "/proc/sys/net/ipv4/ip_forward"])
        self.assertEqual(stdout, "1", "net.ipv4.ip_forward is not set to 1")
        print("  [+] TC1.3 PASSED: Kernel IP Forwarding is active on Edge Router.")

    # --------------------------------------------------------------------------
    # CATEGORY 2: NETWORK SEGMENTATION & PERIMETER FIREWALL POLICIES
    # --------------------------------------------------------------------------
    def test_04_external_to_dmz_connectivity(self):
        """TC2.1: Attacker (10.10.10.5) must be able to reach DMZ Web (10.10.20.50:80)."""
        code, stdout, _ = run_docker_exec(
            CONTAINER_ATTACKER,
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{TARGET_DMZ_IP}/login.php"]
        )
        self.assertIn(stdout, ["200", "302"], f"Expected HTTP 200 or 302 from DMZ Web, got: {stdout}")
        print("  [+] TC2.1 PASSED: External Attacker can reach DMZ Web server (HTTP 200/302).")

    def test_05_external_to_internal_perimeter_blocked(self):
        """TC2.2: Zero-Trust Perimeter - Attacker CANNOT connect to Internal Core (10.10.30.50:5000)."""
        code, stdout, stderr = run_docker_exec(
            CONTAINER_ATTACKER,
            ["nc", "-z", "-w", "2", TARGET_INTERNAL_IP, "5000"]
        )
        self.assertNotEqual(code, 0, "Security Violation: External attacker was able to reach Internal Corporate Asset directly!")
        print("  [+] TC2.2 PASSED: Perimeter Firewall successfully rejected direct External -> Internal probe.")

    def test_06_dmz_to_internal_reachability(self):
        """TC2.3: Lateral Path - DMZ server can query Internal Corporate API via PHP."""
        code, stdout, _ = run_docker_exec(
            CONTAINER_DMZ,
            ["php", "-r", f"echo file_get_contents('http://{TARGET_INTERNAL_IP}:5000/api/v1/health');"]
        )
        self.assertIn("healthy", stdout, f"DMZ unable to communicate with internal API: {stdout}")
        print("  [+] TC2.3 PASSED: DMZ to Internal network path is operational.")

    # --------------------------------------------------------------------------
    # CATEGORY 3: THREAT EMULATION & IDS DETECTION VERIFICATION
    # --------------------------------------------------------------------------
    def test_07_sqli_union_select_detection(self):
        """TC3.1: Suricata must trigger SID 1000010 on SQLi UNION SELECT attempt."""
        run_docker_exec(
            CONTAINER_ATTACKER,
            ["curl", "-s", f"http://{TARGET_DMZ_IP}/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,user()+--+&Submit=Submit"]
        )
        time.sleep(2)
        fast_log = get_suricata_fast_log()
        self.assertIn("1000010", fast_log, "Suricata did NOT trigger SID 1000010 for SQLi UNION SELECT")
        print("  [+] TC3.1 PASSED: Suricata triggered Alert [SID 1000010] SQLi UNION SELECT Pattern.")

    def test_08_automated_scanner_detection(self):
        """TC3.2: Suricata must trigger SID 1000002 when sqlmap User-Agent is detected."""
        run_docker_exec(
            CONTAINER_ATTACKER,
            ["curl", "-s", f"http://{TARGET_DMZ_IP}/vulnerabilities/sqli/?id=1'+or+1=1+--+", "-A", "sqlmap/1.7#stable"]
        )
        time.sleep(2)
        fast_log = get_suricata_fast_log()
        self.assertIn("1000002", fast_log, "Suricata did NOT trigger SID 1000002 for sqlmap scanner detection")
        print("  [+] TC3.2 PASSED: Suricata triggered Alert [SID 1000002] Automated Scanner (sqlmap).")

    def test_09_path_traversal_lfi_detection(self):
        """TC3.3: Suricata must trigger SID 1000020 on /etc/passwd LFI attempt."""
        run_docker_exec(
            CONTAINER_ATTACKER,
            ["curl", "-s", f"http://{TARGET_DMZ_IP}/vulnerabilities/fi/?page=../../../../etc/passwd"]
        )
        time.sleep(2)
        fast_log = get_suricata_fast_log()
        self.assertIn("1000020", fast_log, "Suricata did NOT trigger SID 1000020 for Path Traversal (/etc/passwd)")
        print("  [+] TC3.3 PASSED: Suricata triggered Alert [SID 1000020] Directory Traversal (/etc/passwd).")

    def test_10_lateral_movement_detection(self):
        """TC3.4: Suricata must trigger SID 1000030/1000031 on DMZ -> Internal pivot."""
        run_docker_exec(
            CONTAINER_DMZ,
            ["php", "-r", f"echo file_get_contents('http://{TARGET_INTERNAL_IP}:5000/api/v1/customers');"]
        )
        time.sleep(2)
        fast_log = get_suricata_fast_log()
        matched = ("1000030" in fast_log) or ("1000031" in fast_log)
        self.assertTrue(matched, "Suricata did NOT trigger SID 1000030 or 1000031 on Lateral Movement")
        print("  [+] TC3.4 PASSED: Suricata triggered Alert [SID 1000030/1000031] Lateral Movement DMZ->Internal.")

    def test_11_perimeter_breach_detection(self):
        """TC3.5: Suricata must trigger SID 1000040 on direct Attacker -> Internal probe."""
        run_docker_exec(
            CONTAINER_ATTACKER,
            ["nc", "-z", "-w", "1", TARGET_INTERNAL_IP, "5000"]
        )
        time.sleep(2)
        fast_log = get_suricata_fast_log()
        self.assertIn("1000040", fast_log, "Suricata did NOT trigger SID 1000040 for Perimeter Breach probe")
        print("  [+] TC3.5 PASSED: Suricata triggered Alert [SID 1000040] Perimeter Breach Attempt.")

    # --------------------------------------------------------------------------
    # CATEGORY 4: BLUE TEAM TELEMETRY INTEGRITY
    # --------------------------------------------------------------------------
    def test_12_eve_json_telemetry_schema(self):
        """TC4.1: eve.json must contain structured events with alert metadata."""
        events = get_suricata_eve_json()
        alerts = [e for e in events if e.get("event_type") == "alert"]
        self.assertGreater(len(alerts), 0, "No alert events found in /var/log/suricata/eve.json")
        sample_alert = alerts[0]["alert"]
        self.assertIn("signature_id", sample_alert, "Signature ID missing in eve.json alert object")
        self.assertIn("signature", sample_alert, "Signature description missing in eve.json alert object")
        print(f"  [+] TC4.1 PASSED: Validated {len(alerts)} structured alert events in eve.json telemetry.")


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCyberRangeLab)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
