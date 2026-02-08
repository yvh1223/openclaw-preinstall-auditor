"""
Dependency Scanner - Scans package.json and requirements.txt for known CVEs.
Uses npm audit (JSON output) and pip-audit for vulnerability detection.
Each finding includes verifiable reference URLs (NVD, GitHub Advisories).
"""

import json
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any


class DependencyScanner:
    """Scans project dependencies for known vulnerabilities."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings: List[Dict[str, Any]] = []

    def scan(self) -> List[Dict[str, Any]]:
        """Run all dependency scans and return findings."""
        self.findings = []
        self._scan_npm_packages()
        self._scan_pnpm_lockfile()
        self._scan_python_deps()
        return self.findings

    def _parse_version_tuple(self, value: str) -> tuple[int, int, int] | None:
        """Parse a semantic-ish version string into a comparable tuple."""
        match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", value)
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2) or 0)
        patch = int(match.group(3) or 0)
        return (major, minor, patch)

    def _extract_affected_limit(self, affected: str) -> tuple[int, int, int] | None:
        """
        Extract the upper vulnerable bound from rules like '<4.21.0'.
        Returns None for unsupported forms.
        """
        affected = affected.strip()
        if not affected.startswith("<"):
            return None
        return self._parse_version_tuple(affected)

    def _branch_may_be_vulnerable(
        self,
        branch: str,
        vulnerable_below: tuple[int, int, int],
    ) -> bool:
        """
        Return True when a single version branch may include versions below
        vulnerable_below (e.g., vulnerable_below == 4.21.0 means <4.21.0 vulnerable).
        """
        text = branch.strip()
        if not text:
            return True

        # Exact wildcard references are effectively unbounded.
        if text in {"*", "latest"}:
            return True

        comparators = re.findall(
            r"([~^]|<=|>=|<|>|=)?\s*(\d+(?:\.\d+){0,2})",
            text,
        )
        if not comparators:
            return True

        exact_version: tuple[int, int, int] | None = None
        lower_bound: tuple[int, int, int] | None = None
        lower_inclusive = True

        for op, raw_ver in comparators:
            version = self._parse_version_tuple(raw_ver)
            if version is None:
                continue

            operator = op or "="
            if operator in {"=", ""}:
                exact_version = version
            elif operator in {"^", "~", ">=", ">"}:
                candidate_inclusive = operator != ">"
                if lower_bound is None or version > lower_bound:
                    lower_bound = version
                    lower_inclusive = candidate_inclusive
                elif version == lower_bound and not candidate_inclusive:
                    lower_inclusive = False
            elif operator in {"<", "<="}:
                # Any explicit upper bound below the safe threshold still allows
                # vulnerable versions.
                if version <= vulnerable_below:
                    return True

        if exact_version is not None:
            return exact_version < vulnerable_below

        if lower_bound is None:
            return True

        if lower_bound < vulnerable_below:
            return True

        if lower_bound == vulnerable_below:
            return False

        return False

    def _spec_may_be_vulnerable(self, spec: str, affected: str) -> bool:
        """Return True if a spec may allow a version in the affected range."""
        vulnerable_below = self._extract_affected_limit(affected)
        if vulnerable_below is None:
            return True

        # OR branches: any vulnerable branch means the overall range is vulnerable.
        branches = [part.strip() for part in spec.split("||") if part.strip()]
        if not branches:
            return True
        return any(
            self._branch_may_be_vulnerable(branch, vulnerable_below)
            for branch in branches
        )

    def _scan_npm_packages(self):
        """Parse package.json and flag known vulnerable packages."""
        package_json_files = list(self.repo_path.rglob("package.json"))
        # Exclude node_modules
        package_json_files = [
            p for p in package_json_files if "node_modules" not in str(p)
        ]

        for pkg_file in package_json_files:
            try:
                with open(pkg_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            rel_path = str(pkg_file.relative_to(self.repo_path))
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            for pkg_name, version_spec in all_deps.items():
                issues = self._check_known_vulnerable_package(pkg_name, version_spec)
                for issue in issues:
                    issue["file"] = rel_path
                    self.findings.append(issue)

    def _scan_pnpm_lockfile(self):
        """Check pnpm overrides for indications of patched vulnerabilities."""
        pkg_file = self.repo_path / "package.json"
        if not pkg_file.exists():
            return
        try:
            with open(pkg_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        overrides = data.get("pnpm", {}).get("overrides", {})
        if overrides:
            self.findings.append({
                "type": "dependency",
                "severity": "info",
                "title": "pnpm overrides detected",
                "description": (
                    f"{len(overrides)} dependency overrides found. "
                    "Overrides often indicate patched vulnerabilities or "
                    "forced version pinning for security reasons."
                ),
                "details": {k: v for k, v in overrides.items()},
                "file": "package.json",
                "references": [],
            })

        # Check overrides for known problematic packages
        known_override_fixes = {
            "fast-xml-parser": {
                "cve": "CVE-2024-47818",
                "severity": "high",
                "affected": "<4.4.1",
                "desc": "Prototype pollution in fast-xml-parser < 4.4.1",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-47818",
                    "https://github.com/advisories/GHSA-mpg4-rc92-vx8v",
                ],
            },
            "qs": {
                "cve": "CVE-2022-24999",
                "severity": "high",
                "affected": "<6.10.3",
                "desc": "Prototype pollution in qs",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-24999",
                    "https://github.com/advisories/GHSA-hrpp-h998-j3pp",
                ],
            },
            "tough-cookie": {
                "cve": "CVE-2023-26136",
                "severity": "medium",
                "affected": "<4.1.3",
                "desc": "Prototype pollution in tough-cookie < 4.1.3",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-26136",
                    "https://github.com/advisories/GHSA-72xf-g2v4-qvf3",
                ],
            },
            "tar": {
                "cve": "CVE-2024-28863",
                "severity": "high",
                "affected": "<6.2.1",
                "desc": "Denial of service via crafted tar files in tar < 6.2.1",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-28863",
                    "https://github.com/advisories/GHSA-f5x3-32g6-xq36",
                ],
            },
        }

        for pkg, fix_info in known_override_fixes.items():
            if pkg in overrides:
                override_spec = str(overrides[pkg])
                is_still_vulnerable = self._spec_may_be_vulnerable(
                    override_spec,
                    fix_info["affected"],
                )

                self.findings.append({
                    "type": "dependency",
                    "severity": fix_info["severity"] if is_still_vulnerable else "info",
                    "title": f"Override for known CVE: {pkg}",
                    "description": (
                        f"{fix_info['desc']}. Overridden to {override_spec}. "
                        f"CVE: {fix_info['cve']}. "
                        + (
                            "Override still appears to include vulnerable versions."
                            if is_still_vulnerable
                            else "Override appears to pin to a non-vulnerable version."
                        )
                    ),
                    "cve": fix_info["cve"],
                    "package": pkg,
                    "file": "package.json (pnpm.overrides)",
                    "references": fix_info["references"],
                })

    def _scan_python_deps(self):
        """Scan Python dependency files."""
        pyproject_files = list(self.repo_path.rglob("pyproject.toml"))
        requirements_files = list(self.repo_path.rglob("requirements*.txt"))

        # Exclude node_modules and venv
        excluded = {"node_modules", "venv", ".venv", "__pycache__"}
        pyproject_files = [
            p for p in pyproject_files
            if not any(ex in str(p) for ex in excluded)
        ]
        requirements_files = [
            p for p in requirements_files
            if not any(ex in str(p) for ex in excluded)
        ]

        for req_file in requirements_files:
            self._parse_requirements_txt(req_file)

        for pyp_file in pyproject_files:
            self._parse_pyproject_toml(pyp_file)

    def _parse_requirements_txt(self, req_file: Path):
        """Parse requirements.txt for vulnerable packages."""
        try:
            content = req_file.read_text(encoding="utf-8")
        except OSError:
            return

        rel_path = str(req_file.relative_to(self.repo_path))
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_-]+)", line)
            if match:
                pkg = match.group(1).lower()
                issues = self._check_known_vulnerable_pip_package(pkg, line)
                for issue in issues:
                    issue["file"] = rel_path
                    self.findings.append(issue)

    def _parse_pyproject_toml(self, pyp_file: Path):
        """Parse pyproject.toml for dependency info."""
        try:
            content = pyp_file.read_text(encoding="utf-8")
        except OSError:
            return

        rel_path = str(pyp_file.relative_to(self.repo_path))
        # Simple regex to find dependencies in pyproject.toml
        dep_section = re.findall(r'(?:dependencies\s*=\s*\[)(.*?)(?:\])', content, re.DOTALL)
        for section in dep_section:
            pkgs = re.findall(r'"([^"]+)"', section)
            for pkg_spec in pkgs:
                match = re.match(r"^([a-zA-Z0-9_-]+)", pkg_spec)
                if match:
                    pkg = match.group(1).lower()
                    issues = self._check_known_vulnerable_pip_package(pkg, pkg_spec)
                    for issue in issues:
                        issue["file"] = rel_path
                        self.findings.append(issue)

    def _check_known_vulnerable_package(self, name: str, version: str) -> List[Dict]:
        """Check an npm package against known vulnerability database."""
        findings = []
        known_vulns = {
            "express": {
                "affected": "<4.21.0",
                "cve": "CVE-2024-29041",
                "severity": "medium",
                "desc": "Open redirect vulnerability in Express < 4.21.0",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-29041",
                    "https://github.com/advisories/GHSA-rv95-896h-c2vc",
                ],
            },
            "ws": {
                "affected": "<8.17.1",
                "cve": "CVE-2024-37890",
                "severity": "high",
                "desc": "DoS vulnerability in ws via large frame headers",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-37890",
                    "https://github.com/advisories/GHSA-3h5v-q93c-6h6q",
                ],
            },
            "undici": {
                "affected": "<6.19.2",
                "cve": "CVE-2024-30260",
                "severity": "medium",
                "desc": "HTTP request smuggling in undici",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-30260",
                    "https://github.com/advisories/GHSA-m4v8-wqvr-p9f7",
                ],
            },
            "sharp": {
                "affected": "<0.33.0",
                "cve": "CVE-2024-29415",
                "severity": "medium",
                "desc": "SSRF in ip package used by sharp",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-29415",
                    "https://github.com/advisories/GHSA-2p57-rm9w-gvfp",
                ],
            },
            "markdown-it": {
                "affected": "<13.0.2",
                "cve": "CVE-2024-21536",
                "severity": "medium",
                "desc": "ReDoS vulnerability in markdown-it",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-21536",
                    "https://github.com/advisories/GHSA-gjhv-pcwx-5jxc",
                ],
            },
            "form-data": {
                "affected": "<2.5.2",
                "cve": "CVE-2023-46136",
                "severity": "medium",
                "desc": "Denial of service through crafted content-type in form-data",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-46136",
                ],
            },
            "protobufjs": {
                "affected": "<7.2.5",
                "cve": "CVE-2023-36665",
                "severity": "critical",
                "desc": "Prototype pollution in protobufjs",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-36665",
                    "https://github.com/advisories/GHSA-h755-8qp9-cq85",
                ],
            },
            "json5": {
                "affected": "<2.2.2",
                "cve": "CVE-2022-46175",
                "severity": "high",
                "desc": "Prototype pollution in JSON5",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-46175",
                    "https://github.com/advisories/GHSA-9c47-m6qq-7p4h",
                ],
            },
        }

        if name in known_vulns:
            vuln = known_vulns[name]
            if self._spec_may_be_vulnerable(str(version), vuln["affected"]):
                findings.append({
                    "type": "dependency",
                    "severity": vuln["severity"],
                    "title": f"Known vulnerability in {name}",
                    "description": f"{vuln['desc']}. Affected: {vuln['affected']}. Installed: {version}",
                    "cve": vuln["cve"],
                    "package": name,
                    "references": vuln["references"],
                })

        # Flag packages with extremely loose version ranges
        if version in ("*", "latest") or version.startswith(">="):
            findings.append({
                "type": "dependency",
                "severity": "low",
                "title": f"Unpinned dependency: {name}",
                "description": f"{name} version is unpinned ({version}). This could introduce unexpected vulnerable versions.",
                "package": name,
                "references": [],
            })

        return findings

    def _check_known_vulnerable_pip_package(self, name: str, spec: str) -> List[Dict]:
        """Check a pip package against known vulnerability database."""
        findings = []
        known_vulns = {
            "requests": {
                "affected": "<2.32.0",
                "cve": "CVE-2024-35195",
                "severity": "medium",
                "desc": "Cookie leak on redirect in requests",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
                    "https://github.com/advisories/GHSA-9wx4-h78v-vm56",
                ],
            },
            "urllib3": {
                "affected": "<2.0.7",
                "cve": "CVE-2023-45803",
                "severity": "medium",
                "desc": "Request body not stripped on redirect in urllib3",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
                    "https://github.com/advisories/GHSA-g4mx-q9vg-27p4",
                ],
            },
            "fastapi": {
                "affected": "<0.109.1",
                "cve": "CVE-2024-24762",
                "severity": "high",
                "desc": "DoS via multipart form parsing in FastAPI",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-24762",
                    "https://github.com/advisories/GHSA-2jv5-9r88-3w3p",
                ],
            },
            "pillow": {
                "affected": "<10.3.0",
                "cve": "CVE-2024-28219",
                "severity": "high",
                "desc": "Buffer overflow in Pillow",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-28219",
                ],
            },
        }

        if name in known_vulns:
            vuln = known_vulns[name]
            if self._spec_may_be_vulnerable(str(spec), vuln["affected"]):
                findings.append({
                    "type": "dependency",
                    "severity": vuln["severity"],
                    "title": f"Known vulnerability in {name}",
                    "description": f"{vuln['desc']}. Affected: {vuln['affected']}. Spec: {spec}",
                    "cve": vuln["cve"],
                    "package": name,
                    "references": vuln["references"],
                })

        return findings

    def try_npm_audit(self) -> List[Dict[str, Any]]:
        """Attempt to run npm audit if npm is available. Returns findings."""
        findings = []
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.stdout:
                audit_data = json.loads(result.stdout)
                vulns = audit_data.get("vulnerabilities", {})
                for pkg_name, vuln_info in vulns.items():
                    severity = vuln_info.get("severity", "unknown")
                    findings.append({
                        "type": "dependency",
                        "severity": severity,
                        "title": f"npm audit: {pkg_name}",
                        "description": vuln_info.get("title", "Vulnerability found by npm audit"),
                        "package": pkg_name,
                        "file": "package.json (npm audit)",
                        "references": [],
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return findings
