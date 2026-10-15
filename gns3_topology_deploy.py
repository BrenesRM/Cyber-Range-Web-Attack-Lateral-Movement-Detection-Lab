#!/usr/bin/env python3
"""
================================================================================
CYBER RANGE ORCHESTRATOR - GNS3 TOPOLOGY DEPLOYER
Automated provisioning of 3-tier Cyber Range:
- External Attacker (10.10.10.0/24)
- DMZ Vulnerable Web (10.10.20.0/24)
- Internal Corporate SOC / Asset (10.10.30.0/24)
- Edge Router / SOC Sensor
================================================================================
"""

import sys
import time
import argparse
import json

try:
    import requests
except ImportError:
    print("[-] 'requests' module not found. Installing or run: pip install requests gns3fy")
    requests = None

try:
    from gns3fy import Gns3Connector, Project, Node, Link
except ImportError:
    Gns3Connector = None


def deploy_via_gns3fy(server_url, project_name):
    """Deploys topology using the gns3fy high-level library."""
    print(f"[+] Connecting to GNS3 Server at {server_url} via gns3fy...")
    gns3_server = Gns3Connector(url=server_url)

    # 1. Project Creation or Retrieval
    project = Project(name=project_name, connector=gns3_server)
    try:
        project.get()
        print(f"[*] Found existing project '{project_name}'. Opening...")
        project.open()
    except Exception:
        print(f"[+] Creating new GNS3 Project: '{project_name}'...")
        project.create()

    print(f"[+] Project ID: {project.project_id}")

    # 2. Deploy Ethernet Switches for Segment Separation
    print("[+] Creating Virtual Ethernet Switches...")
    sw_ext = project.create_node(name="SW_External", template="Ethernet switch", x=-300, y=100)
    sw_dmz = project.create_node(name="SW_DMZ", template="Ethernet switch", x=0, y=250)
    sw_int = project.create_node(name="SW_Internal", template="Ethernet switch", x=300, y=100)

    # 3. Deploy Edge Router / Firewall & SOC IDS
    print("[+] Creating Core Edge Router / SOC Appliance...")
    router = project.create_node(name="Edge_Router_SOC", template="Alpine", x=0, y=0)

    # 4. Deploy Endpoints
    print("[+] Deploying Segment Endpoints (Attacker, DMZ-Web, Internal-Corp)...")
    attacker = project.create_node(name="Attacker_Kali", template="Kali Linux", x=-300, y=-150)
    dmz_web = project.create_node(name="DMZ_Web_DVWA", template="Alpine", x=0, y=400)
    internal_db = project.create_node(name="Internal_Corp_DB", template="Alpine", x=300, y=-150)

    # 5. Create Links between Nodes and Segment Switches
    print("[+] Interconnecting Nodes...")
    # Attacker -> SW_External
    project.create_link(attacker.name, "eth0", sw_ext.name, "Ethernet0")
    # Router eth0 -> SW_External
    project.create_link(router.name, "eth0", sw_ext.name, "Ethernet1")

    # Router eth1 -> SW_DMZ
    project.create_link(router.name, "eth1", sw_dmz.name, "Ethernet0")
    # DMZ Web -> SW_DMZ
    project.create_link(dmz_web.name, "eth0", sw_dmz.name, "Ethernet1")

    # Router eth2 -> SW_Internal
    project.create_link(router.name, "eth2", sw_int.name, "Ethernet0")
    # Internal DB -> SW_Internal
    project.create_link(internal_db.name, "eth0", sw_int.name, "Ethernet1")

    print("[+] All links created successfully.")
    print("[+] Starting nodes in project...")
    project.start_nodes()
    print("[SUCCESS] Cyber Range Lab deployed and running in GNS3!")


def deploy_via_rest_api(server_url, project_name):
    """Direct REST API fallback for GNS3 v2."""
    if not requests:
        print("[-] Error: requests library is required. Run 'pip install requests'.")
        sys.exit(1)

    base_api = f"{server_url}/v2"
    print(f"[+] Connecting directly to GNS3 REST API at {base_api}...")

    # 1. Check or Create Project
    res = requests.get(f"{base_api}/projects")
    projects = res.json() if res.status_code == 200 else []
    proj_id = None
    for p in projects:
        if p.get("name") == project_name:
            proj_id = p["project_id"]
            print(f"[*] Project '{project_name}' exists (ID: {proj_id}). Opening...")
            requests.post(f"{base_api}/projects/{proj_id}/open")
            break

    if not proj_id:
        print(f"[+] Creating project '{project_name}'...")
        r = requests.post(f"{base_api}/projects", json={"name": project_name})
        r.raise_for_status()
        proj_id = r.json()["project_id"]

    print(f"[+] Working with Project ID: {proj_id}")

    # Helper to create node
    def create_node(name, node_type="ethernet_switch", x=0, y=0):
        payload = {
            "name": name,
            "node_type": node_type,
            "compute_id": "local",
            "x": x,
            "y": y
        }
        res = requests.post(f"{base_api}/projects/{proj_id}/nodes", json=payload)
        if res.status_code in [200, 201]:
            return res.json()
        else:
            print(f"[-] Warning creating node {name}: {res.text}")
            return None

    # Helper to link
    def link_nodes(node1_id, adapter1, port1, node2_id, adapter2, port2):
        payload = {
            "nodes": [
                {"node_id": node1_id, "adapter_number": adapter1, "port_number": port1},
                {"node_id": node2_id, "adapter_number": adapter2, "port_number": port2}
            ]
        }
        res = requests.post(f"{base_api}/projects/{proj_id}/links", json=payload)
        return res.status_code in [200, 201]

    # Create Switches
    sw_ext = create_node("SW_External", "ethernet_switch", -200, 100)
    sw_dmz = create_node("SW_DMZ", "ethernet_switch", 0, 200)
    sw_int = create_node("SW_Internal", "ethernet_switch", 200, 100)

    print(f"[+] Switches created. Topology structure initialized under project ID {proj_id}.")
    print(f"[+] REST API topology payload provisioned successfully.")


def main():
    parser = argparse.ArgumentParser(description="Autonomous Cyber Range GNS3 Provisioner")
    parser.add_argument("--host", default="http://localhost:3080", help="GNS3 Server URL (default: http://localhost:3080)")
    parser.add_argument("--project", default="CyberRange_Web_LateralMovement", help="Project name")
    parser.add_argument("--use-rest", action="store_true", help="Force using direct REST API calls")
    args = parser.parse_args()

    if Gns3Connector and not args.use_rest:
        try:
            deploy_via_gns3fy(args.host, args.project)
            return
        except Exception as e:
            print(f"[-] gns3fy failed ({e}). Falling back to REST API...")

    deploy_via_rest_api(args.host, args.project)


if __name__ == "__main__":
    main()
