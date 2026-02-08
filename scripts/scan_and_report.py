#!/usr/bin/env python3
"""
McAfee OpenClaw Pre-Install Security Auditor
Main entry point - runs all scanners and generates reports.

Usage:
    python scan_and_report.py --repo <path_to_openclaw_repo>
    python scan_and_report.py --repo <path> --output report.html
    python scan_and_report.py --repo <path> --output report.html --json results.json
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.source_code_scanner import SourceCodeScanner
from src.scanners.skill_scanner import SkillScanner
from src.scanners.vulnerability_scanner import VulnerabilityScanner
from src.analyzers.risk_scorer import RiskScorer
from src.utils.report_generator import ReportGenerator


def print_banner():
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 65)
    print("   McAfee OpenClaw Pre-Install Security Auditor")
    print("   Version 1.0.0 - Real Scanner Engine")
    print("=" * 65)
    print(f"{Style.RESET_ALL}")


def run_scan(
    repo_path: str,
    output_html: str = None,
    output_json: str = None,
    output_txt: str = None,
    report_profile: str = "full",
):
    """Run the full security scan and generate reports."""
    print_banner()

    repo = Path(repo_path)
    if not repo.exists():
        print(f"{Fore.RED}Error: Repository not found at {repo_path}{Style.RESET_ALL}")
        return 1

    print(f"{Fore.CYAN}Target: {repo.resolve()}{Style.RESET_ALL}")
    print()

    all_findings = []
    start_time = time.time()

    # --- Phase 1: Dependency Scanning ---
    print(f"{Fore.YELLOW}[1/4] Scanning dependencies...{Style.RESET_ALL}")
    dep_scanner = DependencyScanner(repo_path)
    dep_findings = dep_scanner.scan()
    all_findings.extend(dep_findings)
    print(f"  {Fore.GREEN}Found {len(dep_findings)} dependency findings{Style.RESET_ALL}")

    # --- Phase 2: Source Code Scanning ---
    print(f"{Fore.YELLOW}[2/4] Scanning source code for malicious patterns...{Style.RESET_ALL}")
    src_scanner = SourceCodeScanner(repo_path)
    src_findings = src_scanner.scan()
    all_findings.extend(src_findings)
    print(f"  {Fore.GREEN}Scanned {src_scanner.files_scanned} files, found {len(src_findings)} findings{Style.RESET_ALL}")

    # --- Phase 3: Skills Scanning ---
    print(f"{Fore.YELLOW}[3/4] Scanning skills repository...{Style.RESET_ALL}")
    skill_scanner = SkillScanner(repo_path)
    skill_findings = skill_scanner.scan()
    all_findings.extend(skill_findings)
    print(f"  {Fore.GREEN}Scanned {skill_scanner.skills_scanned} skills, found {len(skill_findings)} findings{Style.RESET_ALL}")

    # --- Phase 4: Known Vulnerability Scanning (CVE + Architecture) ---
    print(f"{Fore.YELLOW}[4/4] Scanning for known CVEs & architectural weaknesses...{Style.RESET_ALL}")
    vuln_scanner = VulnerabilityScanner(repo_path)
    vuln_findings = vuln_scanner.scan()
    all_findings.extend(vuln_findings)
    cve_count = sum(1 for f in vuln_findings if f.get("cve"))
    print(f"  {Fore.GREEN}Found {len(vuln_findings)} vulnerability findings ({cve_count} CVE-related){Style.RESET_ALL}")

    elapsed = time.time() - start_time

    # --- Risk Scoring ---
    print()
    print(f"{Fore.YELLOW}Calculating risk score...{Style.RESET_ALL}")
    scorer = RiskScorer()
    risk_summary = scorer.calculate(all_findings)

    # --- Print Summary ---
    score = risk_summary["risk_score"]
    level = risk_summary["risk_level"]

    if score >= 70:
        score_color = Fore.RED
    elif score >= 50:
        score_color = Fore.YELLOW
    elif score >= 30:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.GREEN

    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 65}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}   SCAN RESULTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 65}{Style.RESET_ALL}")
    print()
    print(f"  Risk Score:      {score_color}{Style.BRIGHT}{score}/100 ({level}){Style.RESET_ALL}")
    print(f"  Recommendation:  {risk_summary['recommendation']}")
    print()
    print(f"  Total Findings:  {len(all_findings)}")

    sev = risk_summary["severity_breakdown"]
    print(f"    Critical: {Fore.RED}{sev.get('critical', 0)}{Style.RESET_ALL}")
    print(f"    High:     {Fore.YELLOW}{sev.get('high', 0)}{Style.RESET_ALL}")
    print(f"    Medium:   {sev.get('medium', 0)}")
    print(f"    Low:      {sev.get('low', 0)}")
    print(f"    Info:     {sev.get('info', 0)}")
    print()
    print(f"  Scan Time:       {elapsed:.2f}s")
    print(f"  Files Scanned:   {src_scanner.files_scanned}")
    print(f"  Skills Analyzed: {skill_scanner.skills_scanned}")
    print()

    # Print top issues
    top_issues = risk_summary.get("top_issues", [])
    if top_issues:
        print(f"{Fore.CYAN}  Top Issues:{Style.RESET_ALL}")
        for i, issue in enumerate(top_issues[:5], 1):
            sev_str = issue.get("severity", "info").upper()
            if sev_str == "CRITICAL":
                color = Fore.RED
            elif sev_str == "HIGH":
                color = Fore.YELLOW
            else:
                color = ""
            print(f"    {i}. {color}[{sev_str}]{Style.RESET_ALL} {issue.get('title', 'Unknown')}")
            print(f"       {issue.get('file', '')}")
        print()

    print(f"{'=' * 65}")

    # --- Build full results ---
    scan_results = {
        "scan_metadata": {
            "scan_date": datetime.now().isoformat(),
            "scanner_version": "1.0.0",
            "report_profile": report_profile,
            "repo_path": str(repo.resolve()),
            "files_scanned": src_scanner.files_scanned,
            "skills_scanned": skill_scanner.skills_scanned,
            "scan_duration_seconds": round(elapsed, 2),
        },
        "risk_summary": risk_summary,
        "findings": all_findings,
        "skill_metadata": skill_scanner.skill_metadata,
    }

    # --- Generate Reports ---
    report = ReportGenerator(scan_results, report_profile=report_profile)

    if output_html:
        report.save_html(output_html)
        print(f"\n{Fore.GREEN}HTML report saved: {output_html}{Style.RESET_ALL}")

    if output_json:
        report.save_json(output_json)
        print(f"{Fore.GREEN}JSON report saved: {output_json}{Style.RESET_ALL}")

    if output_txt:
        report.save_text(output_txt)
        print(f"{Fore.GREEN}Text report saved: {output_txt}{Style.RESET_ALL}")

    # Always save to reports/ directory
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_html = reports_dir / f"openclaw_audit_{timestamp}.html"
    default_json = reports_dir / f"openclaw_audit_{timestamp}.json"

    if not output_html:
        report.save_html(str(default_html))
        print(f"\n{Fore.GREEN}HTML report saved: {default_html}{Style.RESET_ALL}")
    if not output_json:
        report.save_json(str(default_json))
        print(f"{Fore.GREEN}JSON report saved: {default_json}{Style.RESET_ALL}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="McAfee OpenClaw Pre-Install Security Auditor"
    )
    parser.add_argument(
        "--repo", required=True, help="Path to OpenClaw repository to scan"
    )
    parser.add_argument(
        "--output", "-o", help="Output HTML report path"
    )
    parser.add_argument(
        "--json", help="Output JSON report path"
    )
    parser.add_argument(
        "--text", help="Output text report path"
    )
    parser.add_argument(
        "--report-profile",
        choices=["full", "concise"],
        default="full",
        help="Report verbosity/profile for HTML and text outputs (default: full)",
    )

    args = parser.parse_args()
    sys.exit(run_scan(args.repo, args.output, args.json, args.text, args.report_profile))


if __name__ == "__main__":
    main()
