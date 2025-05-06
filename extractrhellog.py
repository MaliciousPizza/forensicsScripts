# extract_logs.py

import os
import shutil
from pathlib import Path
import argparse

def extract_logs(mount_path, output_dir):
    logs = [
        "var/log/secure",
        "var/log/messages",
        "var/log/audit/audit.log",
        "var/log/cron",
        "var/log/dmesg",
        "var/log/yum.log"
    ]
    journal_dir = Path(mount_path) / "var/log/journal"
    os.makedirs(output_dir, exist_ok=True)

    for log in logs:
        src = Path(mount_path) / log
        if src.exists():
            shutil.copy(src, Path(output_dir) / Path(log).name)
            print(f"[+] Copied {log}")
        else:
            print(f"[-] Missing {log}")

    if journal_dir.exists():
        dest = Path(output_dir) / "journal"
        shutil.copytree(journal_dir, dest, dirs_exist_ok=True)
        print(f"[+] Copied journal directory to {dest}")
    else:
        print("[-] No journal directory found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract RHEL logs from mounted image")
    parser.add_argument("mount_path", help="Path to mounted RHEL image")
    parser.add_argument("output_dir", help="Output directory to store logs")
    args = parser.parse_args()
    extract_logs(args.mount_path, args.output_dir)