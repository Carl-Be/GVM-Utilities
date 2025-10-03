#!/usr/bin/env python3
import argparse
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
import os 

GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")

def control_task(task_id, action):
    connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
    connection.connect()
    gmp = Gmp(connection)

    # Authenticate
    # Authenticate
    gmp.send_command(f"""
    <authenticate>
      <credentials>
        <username>{GVM_USER}</username>
        <password>{GVM_PASS}</password>
      </credentials>
    </authenticate>
    """) 

    if action == "pause":
        gmp.send_command(f'<pause_task task_id="{task_id}"/>')
        print(f"[*] Task {task_id} paused.")
    elif action == "stop":
        gmp.send_command(f'<stop_task task_id="{task_id}"/>')
        print(f"[*] Task {task_id} stopped.")
    elif action == "start":
        gmp.send_command(f'<start_task task_id="{task_id}"/>')
        print(f"[*] Task {task_id} started.")
    elif action == "resume":
        gmp.send_command(f'<resume_task task_id="{task_id}"/>')
        print(f"[*] Task {task_id} resumed.")
    else:
        print("[!] Invalid action. Use 'pause', 'stop', 'start', or 'resume'.")

    gmp.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control a GVM task")
    parser.add_argument("--task-id", required=True, help="Task UUID to control")
    parser.add_argument("--action", required=True, choices=["pause", "stop", "start", "resume"],
                        help="Action to perform on the task")

    args = parser.parse_args()
    control_task(args.task_id, args.action)
