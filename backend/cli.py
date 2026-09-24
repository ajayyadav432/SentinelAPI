import sys
import argparse
import asyncio
from backend.ingestion.spec_parser import SpecParser
from backend.engine.scheduler import ScanScheduler
from backend.reporting.report_gen import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description="SentinelAPI CLI — Zero-Trust API Vulnerability Scanner for CI/CD"
    )
    parser.add_argument("--spec", required=True, help="Path to OpenAPI spec (YAML or JSON)")
    parser.add_argument("--target", required=True, help="Target API Base URL")
    parser.add_argument("--user-a", help="Victim user Bearer token")
    parser.add_argument("--user-b", help="Attacker user Bearer token")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="CRITICAL",
                        help="Exit with error code if findings meet or exceed this severity")
    parser.add_argument("--output", default="scan_report.json", help="Path to save output JSON report")
    parser.add_argument("--html-output", help="Path to save HTML report")

    args = parser.parse_args()

    # Load spec
    with open(args.spec, "r") as f:
        spec_text = f.read()

    spec_dict = SpecParser.parse_content(spec_text)
    parsed = SpecParser.parse_spec(spec_dict, default_base_url=args.target)

    print(f"[+] Loaded spec: {parsed.title} (v{parsed.version}) with {len(parsed.endpoints)} endpoints.")
    print(f"[+] Target base URL: {args.target}")
    print("[*] Starting zero-trust security audit...")

    async def run():
        scheduler = ScanScheduler(
            base_url=args.target,
            user_a_token=args.user_a,
            user_b_token=args.user_b
        )
        return await scheduler.execute_scan(parsed, "ci-scan-run")

    summary = asyncio.run(run())

    print(f"\n[✓] Audit Complete in {summary.duration_seconds}s!")
    print(f"    Total Findings: {summary.findings_count}")
    print(f"    - Critical: {summary.critical_count}")
    print(f"    - High:     {summary.high_count}")
    print(f"    - Medium:   {summary.medium_count}")
    print(f"    - Low:      {summary.low_count}")
    print(f"    Overall Zero-Trust Risk Index: {summary.overall_risk_score}/100")

    # Save report
    with open(args.output, "w") as f:
        f.write(ReportGenerator.generate_json(summary))
    print(f"[+] Saved JSON report to: {args.output}")

    if args.html_output:
        with open(args.html_output, "w") as f:
            f.write(ReportGenerator.generate_html_report(summary))
        print(f"[+] Saved HTML report to: {args.html_output}")

    # Check failure gate
    sev_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    threshold = sev_weights[args.fail_on]

    max_detected = 0
    if summary.critical_count > 0:
        max_detected = 4
    elif summary.high_count > 0:
        max_detected = 3
    elif summary.medium_count > 0:
        max_detected = 2
    elif summary.low_count > 0:
        max_detected = 1

    if max_detected >= threshold:
        print(f"\n[!] GATE FAILURE: Identified vulnerabilities at or above '{args.fail_on}' threshold. Blocking CI/CD pipeline!")
        sys.exit(1)
    else:
        print("\n[✓] GATE PASSED: No blocking vulnerabilities detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
