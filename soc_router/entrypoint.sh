#!/usr/bin/env bash
set -e

echo "[+] Initializing Cyber Range Edge Router & SOC Sensor..."

# 1. Enable IP Forwarding
sysctl -w net.ipv4.ip_forward=1

# 2. Discover Network Interfaces
IF_EXT=$(ip -4 addr show to 10.10.10.0/24 | awk '/inet / {print $NF}')
IF_DMZ=$(ip -4 addr show to 10.10.20.0/24 | awk '/inet / {print $NF}')
IF_INT=$(ip -4 addr show to 10.10.30.0/24 | awk '/inet / {print $NF}')

echo "[-] Interface Mapping:"
echo "    - External (10.10.10.0/24): $IF_EXT"
echo "    - DMZ      (10.10.20.0/24): $IF_DMZ"
echo "    - Internal (10.10.30.0/24): $IF_INT"

# 3. Apply Firewall / Perimeter Routing Rules
iptables -F FORWARD
iptables -P FORWARD DROP

# Allow established connections
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# RULE 1: External can access DMZ (e.g., HTTP Web Server)
iptables -A FORWARD -i "$IF_EXT" -o "$IF_DMZ" -p tcp -d 10.10.20.50 --dport 80 -j ACCEPT
iptables -A FORWARD -i "$IF_EXT" -o "$IF_DMZ" -p icmp -j ACCEPT

# RULE 2: External CANNOT directly reach Internal (Zero-Trust Perimeter)
iptables -A FORWARD -i "$IF_EXT" -o "$IF_INT" -j REJECT --reject-with icmp-port-unreachable

# RULE 3: DMZ can reach Internal (Simulating corporate service interconnect - Lateral Movement path)
iptables -A FORWARD -i "$IF_DMZ" -o "$IF_INT" -j ACCEPT

# Enable NAT MASQUERADE for inter-subnet communication
iptables -t nat -A POSTROUTING -j MASQUERADE

echo "[+] Firewall rules configured successfully."

# 4. Start Suricata IDS on all active segment interfaces (PCAP mode with checksum validation disabled)
echo "[+] Starting Suricata Network IDS Sensor (PCAP multi-interface mode)..."
touch /var/log/suricata/fast.log
touch /var/log/suricata/eve.json
rm -f /var/run/suricata.pid

suricata -c /etc/suricata/suricata.yaml -k none --pcap -D

echo "[+] Suricata IDS is running. Monitoring traffic across all segments."
echo "[+] Logging to /var/log/suricata/fast.log and /var/log/suricata/eve.json"

# Keep container alive and stream alerts
tail -f /var/log/suricata/fast.log
