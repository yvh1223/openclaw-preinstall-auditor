import json
import tempfile
import unittest
from pathlib import Path

from src.scanners.dependency_scanner import DependencyScanner


class DependencyScannerVersionTests(unittest.TestCase):
    def test_spec_vulnerability_matching(self):
        scanner = DependencyScanner(".")
        self.assertFalse(scanner._spec_may_be_vulnerable("^4.21.0", "<4.21.0"))
        self.assertTrue(scanner._spec_may_be_vulnerable("^4.20.0", "<4.21.0"))
        self.assertFalse(scanner._spec_may_be_vulnerable("2.32.5", "<2.32.0"))
        self.assertTrue(scanner._spec_may_be_vulnerable("2.31.0", "<2.32.0"))
        self.assertFalse(scanner._spec_may_be_vulnerable(">=6.2.1", "<6.2.1"))
        self.assertFalse(scanner._spec_may_be_vulnerable(">6.2.1", "<6.2.1"))
        self.assertTrue(scanner._spec_may_be_vulnerable(">=6.0.0 <6.2.1", "<6.2.1"))

    def test_known_vulnerable_package_checks_version(self):
        scanner = DependencyScanner(".")

        safe_findings = scanner._check_known_vulnerable_package("express", "^4.21.0")
        self.assertFalse(any(f.get("cve") == "CVE-2024-29041" for f in safe_findings))

        vulnerable_findings = scanner._check_known_vulnerable_package("express", "^4.20.0")
        self.assertTrue(any(f.get("cve") == "CVE-2024-29041" for f in vulnerable_findings))

    def test_pnpm_override_safe_pin_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            package_json = {
                "pnpm": {
                    "overrides": {
                        "tar": "6.2.1",
                    }
                }
            }
            (repo / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

            scanner = DependencyScanner(str(repo))
            scanner._scan_pnpm_lockfile()

            tar_findings = [f for f in scanner.findings if f.get("package") == "tar"]
            self.assertEqual(len(tar_findings), 1)
            self.assertEqual(tar_findings[0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
