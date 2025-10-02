#!/usr/bin/env python3
import argparse
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree
from collections import defaultdict

def try_float(value):
    try:
        return float(value)
    except:
        return 0.0

def try_int(value):
    try:
        return int(value)
    except:
        return float('inf')

def main(task_id, report_id_arg):
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

    if not report_id_arg:
        task_response = gmp.send_command(f'<get_tasks task_id="{task_id}"/>')
        task_xml = etree.fromstring(task_response.encode())
        task = task_xml.find('task')

        if task is None:
            print(f"[!] Task ID '{task_id}' not found.")
            gmp.disconnect()
            return

        name = task.findtext('name')
        status = task.findtext('status')
        progress = task.findtext('progress')

        print(f"{'Task ID':38}  {'Name':20}  {'Status':10}  {'Progress'}")
        print("-" * 75)
        print(f"{task_id}  {name:20}  {status:10}  {progress}%")

        report_elem = task.find('.//current_report/report')
        if report_elem is None:
            print(f"\nNo report available yet for task: {name}")
            gmp.disconnect()
            return

        report_id = report_elem.get('id')
        print(f"\nResults for task: {name} (Report ID: {report_id})")
    else:
        report_id = report_id_arg
        print(f"Using supplied Report ID: {report_id}")

    report_response = gmp.send_command(f'''
    <get_reports report_id="{report_id}" details="1" ignore_pagination="1">
      <report_format_id>c402cc3e-b531-11e1-9163-406186ea4fc5</report_format_id>
    </get_reports>
    ''')
    report_xml = etree.fromstring(report_response.encode())
    results = report_xml.xpath('//result')

    if not results:
        print("  No results.")
        gmp.disconnect()
        return
    else:
        with open(f"report_{report_id}.xml", "w") as file:
            file.write(results)

    host_map = defaultdict(lambda: {'hostname': None, 'TCP': defaultdict(list), 'UDP': defaultdict(list)})

    for r in results:
        ip = r.findtext('host')
        hostname = r.findtext('hostname')
        port_proto = r.findtext('port')
        service = r.findtext('service')
        vuln = r.findtext('name')
        severity = r.findtext('severity')

        if not all([ip, port_proto]):
            continue

        proto = 'TCP' if port_proto.endswith('/tcp') else 'UDP'
        port = port_proto.split('/')[0]

        host_map[ip]['hostname'] = hostname
        if try_float(severity) > 0.0:
            host_map[ip][proto][port].append((vuln, severity))
        else:
            _ = host_map[ip][proto][port]

    for ip, data in host_map.items():
        print(f"{ip}:")
        for proto in ['TCP', 'UDP']:
            print(f"- {proto} Ports")
            for port in sorted(data[proto], key=try_int):
                vulns = data[proto][port]
                print(f"    {port}")
                seen = set()
                for vuln, severity in vulns:
                    key = f"{severity}|{vuln}"
                    if key not in seen:
                        seen.add(key)
                        print(f"        [{severity}] {vuln}")

    gmp.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query GVM report by task ID or report ID")
    parser.add_argument("--task-id", help="Task UUID to retrieve results for")
    parser.add_argument("--report-id", help="Use this Report ID directly instead of task's current report")
    args = parser.parse_args()

    if not args.task_id and not args.report_id:
        parser.error("You must provide --task-id or --report-id")

    main(args.task_id, args.report_id)
