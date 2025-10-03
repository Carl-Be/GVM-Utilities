#!/usr/bin/env python3
import argparse
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree
import os 

GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")

def try_float(value):
    try:
        return float(value)
    except:
        return 0.0

def get_task_details(gmp, task_id):
    response = gmp.send_command(f'<get_tasks task_id="{task_id}"/>')
    root = etree.fromstring(response.encode())
    return root.find('task')

def get_all_tasks(gmp):
    response = gmp.send_command('<get_tasks/>')
    root = etree.fromstring(response.encode())
    return root.xpath('//task')

def main(mode, task_id_filter):
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

    tasks = [get_task_details(gmp, task_id_filter)] if task_id_filter else get_all_tasks(gmp)

    print(f"{'Task ID':38}  {'Name':20}  {'Status':10}  {'Progress'}")
    print("-" * 75)

    for task in tasks:
        if task is None:
            print(f"[!] Task ID '{task_id_filter}' not found.")
            continue

        task_id = task.get('id')
        name = task.findtext('name')
        status = task.findtext('status')
        progress = task.findtext('progress')
        print(f"{task_id}  {name:20}  {status:10}  {progress}%")

        if mode == "status":
            continue

        report_elem = task.find('.//current_report/report')
        if report_elem is None:
            print(f"  No report available yet for task: {name}")
            continue

        report_id = report_elem.get('id')
        print(f"\n  Results for task: {name} (Report ID: {report_id})")

        report_response = gmp.send_command(f'''
        <get_reports report_id="{report_id}" details="1" ignore_pagination="1">
          <report_format_id>c402cc3e-b531-11e1-9163-406186ea4fc5</report_format_id>
        </get_reports>
        ''')
        report_xml = etree.fromstring(report_response.encode())
        results = report_xml.xpath('//result')

        # Filter actionable vulnerabilities
        sorted_results = sorted(
            [r for r in results if try_float(r.findtext('severity')) > 0.0],
            key=lambda r: try_float(r.findtext('severity')),
            reverse=True
        )

        if not sorted_results:
            print("    No actionable results.")
            continue

        for result in sorted_results:
            vuln_name = result.findtext('name')
            severity = result.findtext('severity')
            host = result.findtext('host')
            port = result.findtext('port')
            print(f"    [{severity}] {vuln_name} on {host}:{port}")

    gmp.disconnect()
    print("\nDone.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View GVM task statuses or results")
    parser.add_argument("--mode", choices=["status", "full"], required=True, help="Display only status or include vulnerabilities")
    parser.add_argument("--task-id", help="UUID of a specific task to view")
    args = parser.parse_args()
    main(args.mode, args.task_id)
