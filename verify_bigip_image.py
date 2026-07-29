#!/usr/bin/env python3
"""
verify_bigip_image.py

Walks a mounted BIG-IP image (or any directory tree), computes the SHA-512
hash of every file, and checks it against an F5 BIG-IP NDJSON checksum
manifest (e.g. BIG-IP-15_x-ALL.ndjson).

Efficiency approach:
    - The manifest is loaded ONCE and converted into a dict keyed by
      sha512 hash -> list of {file_name, file_path} entries. This gives
      O(1) average-case lookups per hashed file instead of re-scanning
      hundreds of thousands of manifest lines for every file on disk.
    - Files are hashed in streaming (chunked) fashion so large files
      don't need to be loaded fully into memory.

For each file found on the image, this reports one of:
    MATCH       - hash found in manifest AND file_name matches
    HASH_ONLY   - hash found in manifest but under a different file_name
    UNKNOWN     - hash not found in manifest at all

Usage:
    python3 verify_bigip_image.py --manifest BIG-IP-15_x-ALL.ndjson --image-root /mnt/image
    python3 verify_bigip_image.py --manifest BIG-IP-15_x-ALL.ndjson --image-root /mnt/image --report results.csv
"""

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from collections import defaultdict

CHUNK_SIZE = 1024 * 1024  # 1 MB read chunks for hashing


def load_manifest(manifest_path: Path):
    """Load ndjson manifest into a dict: sha512 -> list of (file_name, file_path)."""
    index = defaultdict(list)
    total_records = 0
    total_hashes = 0

    with open(manifest_path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [warn] skipping malformed manifest line {line_num}: {e}", file=sys.stderr)
                continue

            total_records += 1
            file_name = d.get("file_name")
            file_path = d.get("file_path")
            checksum = d.get("sha512_checksum")

            hashes = checksum if isinstance(checksum, list) else [checksum]
            for h in hashes:
                if not h:
                    continue
                index[h.lower()].append({"file_name": file_name, "file_path": file_path})
                total_hashes += 1

    print(f"Loaded manifest: {total_records} file records, {total_hashes} hash entries indexed.")
    return index


def hash_file(path: Path):
    """Compute sha512 of a file, streaming in chunks."""
    h = hashlib.sha512()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
    except (OSError, PermissionError) as e:
        return None, str(e)
    return h.hexdigest(), None


def walk_and_verify(image_root: Path, index: dict, report_path: Path = None):
    results = []
    counts = {"MATCH": 0, "HASH_ONLY": 0, "UNKNOWN": 0, "ERROR": 0}

    all_files = [p for p in image_root.rglob("*") if p.is_file()]
    total = len(all_files)
    print(f"Found {total} files under {image_root}. Hashing...")

    for i, path in enumerate(all_files, start=1):
        digest, err = hash_file(path)
        rel_path = str(path.relative_to(image_root))
        disk_name = path.name

        if err:
            counts["ERROR"] += 1
            results.append({
                "disk_path": rel_path,
                "disk_name": disk_name,
                "sha512": None,
                "status": "ERROR",
                "manifest_file_name": None,
                "manifest_file_path": None,
                "detail": err,
            })
            continue

        matches = index.get(digest)
        if not matches:
            counts["UNKNOWN"] += 1
            results.append({
                "disk_path": rel_path,
                "disk_name": disk_name,
                "sha512": digest,
                "status": "UNKNOWN",
                "manifest_file_name": None,
                "manifest_file_path": None,
                "detail": "hash not found in manifest",
            })
            continue

        name_match = next((m for m in matches if m["file_name"] == disk_name), None)
        if name_match:
            counts["MATCH"] += 1
            results.append({
                "disk_path": rel_path,
                "disk_name": disk_name,
                "sha512": digest,
                "status": "MATCH",
                "manifest_file_name": name_match["file_name"],
                "manifest_file_path": name_match["file_path"],
                "detail": "",
            })
        else:
            # Hash exists in manifest, but under different filename(s)
            counts["HASH_ONLY"] += 1
            other_names = ", ".join(sorted({m["file_name"] for m in matches}))
            results.append({
                "disk_path": rel_path,
                "disk_name": disk_name,
                "sha512": digest,
                "status": "HASH_ONLY",
                "manifest_file_name": other_names,
                "manifest_file_path": matches[0]["file_path"],
                "detail": "hash matched but under a different file_name in manifest",
            })

        if i % 500 == 0 or i == total:
            print(f"  ...{i}/{total} files processed")

    if report_path:
        with open(report_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "disk_path", "disk_name", "sha512", "status",
                "manifest_file_name", "manifest_file_path", "detail"
            ])
            writer.writeheader()
            writer.writerows(results)
        print(f"Report written to {report_path}")

    print("\nSummary:")
    for k, v in counts.items():
        print(f"  {k}: {v}")

    return results, counts


def main():
    parser = argparse.ArgumentParser(description="Verify files on a mounted image against a BIG-IP NDJSON manifest.")
    parser.add_argument("--manifest", required=True, help="Path to the BIG-IP .ndjson manifest file")
    parser.add_argument("--image-root", required=True, help="Path to the mounted image / directory to scan")
    parser.add_argument("--report", default=None, help="Optional path to write a CSV report (default: report.csv next to image root)")
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    image_root = Path(args.image_root).expanduser().resolve()

    if not manifest_path.exists():
        print(f"Error: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    if not image_root.exists():
        print(f"Error: image root not found: {image_root}", file=sys.stderr)
        sys.exit(1)

    report_path = Path(args.report).expanduser().resolve() if args.report else image_root.parent / "verify_report.csv"

    index = load_manifest(manifest_path)
    walk_and_verify(image_root, index, report_path)


if __name__ == "__main__":
    main()
