import unittest

from src.utils.report_generator import ReportGenerator


class ReportGeneratorQualityTests(unittest.TestCase):
    def setUp(self):
        self.scan_results = {
            "scan_metadata": {
                "repo_path": "/tmp/openclaw",
                "files_scanned": 10,
                "skills_scanned": 2,
                "scan_duration_seconds": 1.23,
            },
            "risk_summary": {
                "risk_score": 65,
                "risk_level": "HIGH",
                "recommendation": "Review before install",
                "severity_breakdown": {
                    "critical": 1,
                    "high": 1,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
                "category_breakdown": {
                    "dangerous_command": 1,
                    "cve": 1,
                    "credential_harvesting": 1,
                },
            },
            "findings": [
                {
                    "severity": "critical",
                    "type": "source_code",
                    "category": "dangerous_command",
                    "title": "Remote code execution via pipe",
                    "description": "curl | bash pattern",
                    "file": "src/install.sh",
                    "line": 12,
                    "references": ["https://attack.mitre.org/techniques/T1059/004/"],
                },
                {
                    "severity": "high",
                    "type": "vulnerability",
                    "category": "cve",
                    "title": "CVE-2026-25253",
                    "description": "gatewayUrl token exfiltration",
                    "file": "ui/src/ui/app-settings.ts",
                    "line": 44,
                    "cve": "CVE-2026-25253",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-25253"],
                },
                {
                    "severity": "medium",
                    "type": "source_code",
                    "category": "credential_harvesting",
                    "title": "Credential token string in docs",
                    "description": "example reference",
                    "file": "README.md",
                    "line": 9,
                    "references": [],
                },
            ],
        }

    def test_text_report_contains_triage_sections(self):
        report = ReportGenerator(self.scan_results, report_profile="full")
        text = report._build_text()

        self.assertIn("TOP CATEGORIES", text)
        self.assertIn("MOST AFFECTED FILES (CRITICAL/HIGH)", text)
        self.assertIn("Context Findings:", text)
        self.assertIn("Duration:", text)

    def test_html_report_contains_filter_controls_and_context_flags(self):
        report = ReportGenerator(self.scan_results, report_profile="full")
        html_output = report._build_html()

        self.assertIn('id="findingSearch"', html_output)
        self.assertIn('id="hideContextFindings"', html_output)
        self.assertIn('data-context="1"', html_output)  # README.md finding
        self.assertIn('data-severity="critical"', html_output)

    def test_concise_profile_labels_present(self):
        report = ReportGenerator(self.scan_results, report_profile="concise")
        html_output = report._build_html()
        text_output = report._build_text()

        self.assertIn("Concise Executive Report", html_output)
        self.assertIn("Executive Summary", html_output)
        self.assertIn("Report Profile:  CONCISE", text_output)
        self.assertIn("TOP FINDINGS (CONCISE)", text_output)


if __name__ == "__main__":
    unittest.main()
