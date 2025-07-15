#!/usr/bin/env python3
import sys
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree

def get_id_by_name(gmp, command, tag, match_name):
    resp = gmp.send_command(f"<{command}/>")
    root = etree.fromstring(resp.encode())
    for item in root.findall(tag):
        name = item.findtext("name")
        if name and name.strip().lower() == match_name.lower():
            return item.get("id")
    raise RuntimeError(f"[!] '{match_name}' not found in {command}")

def create_scan(target_file, task_name, target_name):
    connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
    connection.connect()
    gmp = Gmp(connection)

    # Authenticate
    gmp.send_command('''
    <authenticate>
      <credentials>
        <username>YOUR USERNAME HERE</username>
        <password>YOUR PASSWORD HERE</password>
      </credentials>
    </authenticate>
    ''')

    # Resolve config, scanner, and port list dynamically
    config_id = get_id_by_name(gmp, "get_configs", "config", "Full and fast")
    scanner_id = get_id_by_name(gmp, "get_scanners", "scanner", "OpenVAS Default")
    port_list_id = get_id_by_name(gmp, "get_port_lists", "port_list", "All TCP and Nmap top 100 UDP")

    print(f"[*] Using Config: {config_id}")
    print(f"[*] Using Scanner: {scanner_id}")
    print(f"[*] Using Port List: {port_list_id}")

    # Read IPs
    with open(target_file, 'r') as f:
        ip_list = [line.strip() for line in f if line.strip()]
    ip_targets = ",".join(ip_list)
    print(f"[*] Loaded {len(ip_list)} IPs from {target_file}")

    # Create target
    target_response = gmp.send_command(f'''
    <create_target>
      <name>{target_name}</name>
      <hosts>{ip_targets}</hosts>
      <port_list id="{port_list_id}"/>
    </create_target>
    ''')
    target_id = etree.fromstring(target_response.encode()).get("id")
    print(f"[*] Created target: {target_name} ({target_id})")

    # Create task
    task_response = gmp.send_command(f'''
    <create_task>
      <name>{task_name}</name>
      <config id="{config_id}"/>
      <target id="{target_id}"/>
      <scanner id="{scanner_id}"/>
    </create_task>
    ''')
    task_id = etree.fromstring(task_response.encode()).get("id")
    print(f"[*] Created task: {task_name} ({task_id})")

    # Start scan
    gmp.send_command(f'<start_task task_id="{task_id}"/>')
    print(f"[*] Scan started.")

    gmp.disconnect()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 create_gvm_scan_from_list.py <targets.txt> <scan_name> <target_name>")
        sys.exit(1)
    create_scan(sys.argv[1], sys.argv[2], sys.argv[3])
