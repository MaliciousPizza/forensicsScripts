#!/usr/bin/env python3
"""
parse_bigip_ndjson.py

Parses an F5 BIG-IP-style NDJSON checksum manifest and extracts:
    file_name, file_path, sha512_checksum

Handles the fact that "sha512_checksum" may be either a single string
or a list of strings (when a file has multiple known-good hashes across
versions/builds). Flattens list values into one row per checksum so the
output can be directly joined/queried against another dataset.

Usage:
    python3 parse_bigip_ndjson.py /path/to/input.ndjson
    python3 parse_bigip_ndjson.py /path/to/input.ndjson -o /path/to/output_dir

Outputs (written next to the input file, or to -o/--output-dir if given):
    <input_stem>_parsed.csv    one row per (file_name, file_path, checksum)
    <input_stem>_parsed.json   one record per file, checksum kept as string or list
"""

import argparse
import csv
import json
import sys
from pathlib import Path


def parse_ndjson(input_path: Path):
    records = []
    rows = []
    skipped = 0

    with open(input_path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  [warn] skipping malformed line {line_num}: {e}", file=sys.stderr)
                skipped += 1
                continue

            file_name = d.get("file_name")
            file_path = d.get("file_path")
            checksum = d.get("sha512_checksum")

            records.append({
                "file_name": file_name,
                "file_path": file_path,
                "sha512_checksum": checksum,
            })

            if isinstance(checksum, list):
                for c in checksum:
                    rows.append({"file_name": file_name, "file_path": file_path, "sha512_checksum": c})
            else:
                rows.append({"file_name": file_name, "file_path": file_path, "sha512_checksum": checksum})

    return records, rows, skipped


def main():
    parser = argparse.ArgumentParser(description="Parse a BIG-IP NDJSON checksum manifest into CSV/JSON.")
    parser.add_argument("input", help="Path to the .ndjson file to parse")
    parser.add_argument(
        "-o", "--output-dir",
        default=None,
        help="Directory to write outputs to (default: same directory as input file)"
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else input_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    out_csv = output_dir / f"{input_path.stem}_parsed.csv"
    out_json = output_dir / f"{input_path.stem}_parsed.json"

    print(f"Parsing {input_path} ...")
    records, rows, skipped = parse_ndjson(input_path)

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "file_path", "sha512_checksum"])
        writer.writeheader()
        writer.writerows(rows)

    with open(out_json, "w") as f:
        json.dump(records, f, indent=2)

    print(f"Total file records:        {len(records)}")
    print(f"Total flattened rows:      {len(rows)}")
    if skipped:
        print(f"Skipped malformed lines:   {skipped}")
    print(f"CSV written to:  {out_csv}")
    print(f"JSON written to: {out_json}")


if __name__ == "__main__":
    main()
