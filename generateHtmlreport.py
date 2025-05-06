# generate_html_report.py

from pathlib import Path
import argparse

def generate_html(report_dir, output_file):
    report_dir = Path(report_dir)
    with open(output_file, "w") as out:
        out.write("<html><head><title>RHEL 8 Threat Hunt Report</title></head><body>")
        out.write(f"<h1>Threat Hunt Report - {report_dir.name}</h1>")

        for file in sorted(report_dir.glob("*")):
            if file.suffix in [".txt", ".log", ".sha256"]:
                out.write(f"<h2>{file.name}</h2><pre>")
                try:
                    content = file.read_text(encoding="utf-8", errors="replace")
                    out.write(content[:100000])  # Limit to 100k chars
                except Exception as e:
                    out.write(f"ERROR: Cannot read {file.name}: {str(e)}")
                out.write("</pre><hr>")

        out.write("</body></html>")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HTML report from threat hunt logs")
    parser.add_argument("report_dir", help="Directory containing text/log output files")
    parser.add_argument("output_file", help="Path to output HTML report")
    args = parser.parse_args()
    generate_html(args.report_dir, args.output_file)