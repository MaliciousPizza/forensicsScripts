#!/usr/bin/env python3
"""
log_date_scanner.py

Recursively walks a directory tree, finds every log file it can, and
determines the FIRST and LAST timestamp present in each one. Results are
printed as a Markdown table.

Handles mixed log-rotation naming schemes out of the box:
    access.log  access.log.1  access.log.old  access.log.gz  syslog  auth.log
(basically: any filename, any extension, gzip or plain text)

Understands (auto-detected per line, in this priority order):
    1. Linux audit  ->  msg=audit(1690000000.123:456):     (epoch.msec)
    2. ISO 8601     ->  2024-01-01T00:00:00 / 2024-01-01 00:00:00
    3. Apache/nginx common+combined log format
                    ->  [10/Oct/2023:13:55:36 +0000]
    4. Palo Alto (and other) slash-style dates
                    ->  2023/10/10 13:55:36
    5. Traditional syslog (rsyslog/journald classic format)
                    ->  Oct 10 13:55:36            (no year in-line;
                                                     year inferred from the
                                                     file's mtime)
    6. Bare 10-digit epoch seconds as a last resort
                    ->  1696939936

Usage:
    python3 log_date_scanner.py /var/log --partition sda1
    python3 log_date_scanner.py /mnt/evidence/var/log --partition sdb2 -o report.md
"""

import argparse
import gzip
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Timestamp patterns
# ---------------------------------------------------------------------------
# Each entry is (name, compiled_regex, parser_fn)
# parser_fn(match, file_year) -> datetime or None
# Ordered from most specific/unambiguous to least, since the first pattern
# that matches a given line wins (we don't keep scanning a line once we
# have a hit, for speed).

_MULTISPACE_RE = re.compile(r"\s+")


def _parse_audit_epoch(match, file_year):
    try:
        return datetime.fromtimestamp(float(match.group(1)), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _parse_iso_t(match, file_year):
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _parse_iso_space(match, file_year):
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _parse_apache_clf(match, file_year):
    try:
        return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def _parse_slash_date(match, file_year):
    try:
        return datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def _parse_syslog_traditional(match, file_year):
    text = _MULTISPACE_RE.sub(" ", match.group(1).strip())
    year = file_year or datetime.now().year
    try:
        return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _parse_bare_epoch(match, file_year):
    try:
        ts = float(match.group(1))
        # Sanity window: 2001-09-09 .. 2038-01-19. Keeps us from treating
        # random large numbers (PIDs, sizes, ports) in log lines as dates.
        if 1_000_000_000 <= ts <= 2_147_483_647:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
    return None


PATTERNS = [
    ("audit_epoch", re.compile(r"audit\((\d{10}\.\d+):\d+\)"), _parse_audit_epoch),
    ("iso_t", re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), _parse_iso_t),
    ("iso_space", re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"), _parse_iso_space),
    ("apache_clf", re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[+-]\d{4}\]"), _parse_apache_clf),
    ("paloalto_slash", re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"), _parse_slash_date),
    ("syslog_traditional", re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"), _parse_syslog_traditional),
    ("bare_epoch", re.compile(r"(?<!\d)(\d{10})(?:\.\d+)?(?!\d)"), _parse_bare_epoch),
]

LOG_EMPTY = "LOG EMPTY"
NO_DATE_FOUND = "NO DATE FOUND"
READ_ERROR = "READ ERROR"


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _is_gzip(path):
    """Detect gzip by magic bytes rather than trusting the extension, since
    rotated logs are sometimes compressed without a .gz suffix."""
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def _open_text(path):
    if _is_gzip(path):
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="rt", encoding="utf-8", errors="replace")


def scan_file(path):
    """Returns (first_dt_or_None, last_dt_or_None, status_str_or_None).

    status_str is set (and the dt values are None) for the special cases:
    LOG EMPTY, NO DATE FOUND, or READ ERROR.
    """
    try:
        if os.path.getsize(path) == 0:
            return None, None, LOG_EMPTY
    except OSError:
        return None, None, READ_ERROR

    try:
        file_year = datetime.fromtimestamp(os.path.getmtime(path)).year
    except OSError:
        file_year = datetime.now().year

    first_dt = None
    last_dt = None
    saw_any_line = False

    try:
        with _open_text(path) as fh:
            for line in fh:
                if not line.strip():
                    continue
                saw_any_line = True
                for _name, pattern, parser in PATTERNS:
                    m = pattern.search(line)
                    if not m:
                        continue
                    dt = parser(m, file_year)
                    if dt is None:
                        continue
                    if first_dt is None or dt < first_dt:
                        first_dt = dt
                    if last_dt is None or dt > last_dt:
                        last_dt = dt
                    break  # stop at first matching pattern for this line
    except (OSError, EOFError, gzip.BadGzipFile):
        return None, None, READ_ERROR
    except UnicodeDecodeError:
        return None, None, READ_ERROR

    if not saw_any_line:
        return None, None, LOG_EMPTY

    if first_dt is None:
        return None, None, NO_DATE_FOUND

    return first_dt, last_dt, None


def iter_files(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build_table(root, partition):
    rows = []
    for path in sorted(iter_files(root)):
        rel = os.path.relpath(path, root)
        first_dt, last_dt, status = scan_file(path)
        if status is not None:
            rows.append((partition, rel, status, status))
        else:
            rows.append((partition, rel, fmt_dt(first_dt), fmt_dt(last_dt)))
    return rows


def render_markdown(rows):
    header = "| Partition | File | First Log Date | Last Log Date |"
    sep = "|---|---|---|---|"
    lines = [header, sep]
    for partition, rel, first, last in rows:
        # escape pipe characters that would break the table
        rel_esc = rel.replace("|", "\\|")
        lines.append(f"| {partition} | {rel_esc} | {first} | {last} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Recursively find the first and last log date in every "
                     "file under a directory and output a Markdown table."
    )
    parser.add_argument(
        "directory",
        help="Directory to scan recursively for log files.",
    )
    parser.add_argument(
        "--partition", "-p",
        required=True,
        help="Partition/source label to place in the first column of the table.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional path to write the Markdown table to. "
             "Prints to stdout if omitted.",
    )
    args = parser.parse_args(argv)

    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a directory.", file=sys.stderr)
        return 1

    rows = build_table(args.directory, args.partition)
    table = render_markdown(rows)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(table + "\n")
        print(f"Wrote {len(rows)} rows to {args.output}", file=sys.stderr)
    else:
        print(table)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
