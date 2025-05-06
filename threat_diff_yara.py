#!/usr/bin/env python3
# threat_diff_yara.py
# Python script to compare two directories (baseline vs. suspect) and optionally scan with YARA

import os
import hashlib
import argparse
import csv
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

def hash_file(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"ERROR: {str(e)}"

def walk_and_hash(directory):
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            relative_path = os.path.relpath(full_path, directory)
            file_hashes[relative_path] = hash_file(full_path)
    return file_hashes

def compare_hashes(baseline_hashes, current_hashes):
    added = []
    removed = []
    modified = []

    for path in baseline_hashes:
        if path not in current_hashes:
            removed.append(path)
        elif baseline_hashes[path] != current_hashes[path]:
            modified.append(path)

    for path in current_hashes:
        if path not in baseline_hashes:
            added.append(path)

    return added, removed, modified

def run_yara_scan(directory, yara_rules):
    matches = []
    rules = yara.compile(filepath=yara_rules)
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                match = rules.match(full_path)
                if match:
                    matches.append((full_path, [str(m) for m in match]))
            except Exception as e:
                continue
    return matches

def save_report(added, removed, modified, yara_matches, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'file_diff_report.csv'), 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type', 'File'])
        for f in added:
            writer.writerow(['Added', f])
        for f in removed:
            writer.writerow(['Removed', f])
        for f in modified:
            writer.writerow(['Modified', f])

    if yara_matches:
        with open(os.path.join(out_dir, 'yara_matches.txt'), 'w') as f:
            for path, rules in yara_matches:
                f.write(f"{path} matched rules: {', '.join(rules)}\n")

def main():
    parser = argparse.ArgumentParser(description="Compare two directories and optionally run YARA scan.")
    parser.add_argument("baseline", help="Path to baseline directory")
    parser.add_argument("current", help="Path to current image directory")
    parser.add_argument("--yara", help="YARA rule file to scan with", default=None)
    parser.add_argument("--out", help="Output report directory", default="threat_report")

    args = parser.parse_args()

    print("[*] Hashing baseline directory...")
    baseline_hashes = walk_and_hash(args.baseline)
    print("[*] Hashing current directory...")
    current_hashes = walk_and_hash(args.current)

    print("[*] Comparing hashes...")
    added, removed, modified = compare_hashes(baseline_hashes, current_hashes)

    yara_matches = []
    if args.yara:
        if not YARA_AVAILABLE:
            print("[!] YARA module not installed. Install with `pip install yara-python`.")
        else:
            print("[*] Running YARA scan...")
            yara_matches = run_yara_scan(args.current, args.yara)

    print("[*] Writing report to:", args.out)
    save_report(added, removed, modified, yara_matches, args.out)
    print("[+] Done.")

if __name__ == "__main__":
    main()