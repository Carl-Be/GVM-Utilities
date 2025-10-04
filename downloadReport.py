#!/usr/bin/env python3
import argparse
import os
import re
import requests
from lxml import etree
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

# Env creds
GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")

# GUI endpoint + format + filter EXACTLY like GSA
GSA_URL = "https://127.0.0.1:9392"
XML_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
FILTER_STRING = "apply_overrides=0 levels=hmlg rows=-1 min_qod=70 first=1 sort-reverse=severity notes=1 overrides=1"

def resolve_report_id_from_task(task_id):
    connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
    connection.connect()
    gmp = Gmp(connection)

    # Authenticate
    gmp.send_command(f"""
    <authenticate>
      <credentials>
        <username>{GVM_USER}</username>
        <password>{GVM_PASS}</password>
      </credentials>
    </authenticate>
    """)

    # Get task
    task_response = gmp.send_command(f'<get_tasks task_id="{task_id}"/>')
    task_xml = etree.fromstring(task_response.encode())
    task = task_xml.find('task')
    if task is None:
        gmp.disconnect()
        raise RuntimeError(f"[!] Task ID '{task_id}' not found.")

    # Your original path (legacy schema)
    report_elem = task.find('.//current_report/report')
    report_id = report_elem.get('id') if report_elem is not None else None

    # Fallback for newer GVM where <current_report> is gone
    if not report_id:
        newer = task.find('.//report')
        if newer is not None and newer.get('id'):
            report_id = newer.get('id')

    gmp.disconnect()

    if not report_id:
        raise RuntimeError(f"[!] No report available yet for task: {task_id}. Is the scan finished?")
    return report_id

def login_get_token(session: requests.Session):
    # Exact multipart form the GUI sends
    login_url = f"{GSA_URL}/gmp"
    files = {
        'cmd': (None, 'login'),
        'login': (None, GVM_USER),
        'password': (None, GVM_PASS),
    }
    resp = session.post(login_url, files=files, verify=False)
    if resp.status_code != 200:
        raise RuntimeError(f"[!] Login failed, HTTP {resp.status_code}")

    # Extract <token>...</token> from XML envelope
    try:
        root = etree.fromstring(resp.content)
        token = root.findtext('token')
    except Exception:
        token = None

    if not token:
        # fallback regex if parsing fails
        m = re.search(r"<token>([a-f0-9-]+)</token>", resp.text)
        token = m.group(1) if m else None

    if not token:
        raise RuntimeError("[!] Failed to extract token from login response.")
    return token

def download_report_gui(session: requests.Session, token: str, report_id: str):
    # Exact GET that the GUI issues
    params = {
        'token': token,
        'cmd': 'get_report',
        'details': '1',
        'report_id': report_id,
        'report_config_id': '',
        'report_format_id': XML_FORMAT_ID,
        'filter': FILTER_STRING,
    }
    url = f"{GSA_URL}/gmp"
    resp = session.get(url, params=params, verify=False)
    if resp.status_code != 200:
        raise RuntimeError(f"[!] Report download failed, HTTP {resp.status_code}")

    out = f"report_{report_id}.xml"
    with open(out, 'wb') as f:
        f.write(resp.content)
    print(f"[+] Saved AttackForge-compatible XML report to {out}")

def main(task_id):
    # Resolve report id via socket using your schema
    print(f"[*] Resolving report ID for task {task_id} ...")
    report_id = resolve_report_id_from_task(task_id)
    print(f"[+] Report ID: {report_id}")

    # Mimic browser: login + GET with token + cookie
    requests.packages.urllib3.disable_warnings()  # self-signed on 127.0.0.1
    session = requests.Session()
    token = login_get_token(session)
    print(f"[+] Token: {token}")

    print("[*] Downloading XML via GUI endpoint ...")
    download_report_gui(session, token, report_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query GVM report by task ID and download GUI-identical XML")
    parser.add_argument("--task-id", required=True, help="Task UUID to retrieve results for")
    args = parser.parse_args()
    main(args.task_id)
