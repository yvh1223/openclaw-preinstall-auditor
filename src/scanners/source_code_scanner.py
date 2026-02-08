"""
Source Code Scanner - Static analysis for malicious patterns.
Detects Base64 payloads, known malicious IPs, credential harvesting,
code obfuscation, suspicious shell commands, SSRF, path traversal,
library injection, and crypto mining indicators.
"""

import re
import base64
import os
from pathlib import Path
from typing import List, Dict, Any


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    ".py", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".toml", ".json",
    ".md", ".mdx",
    ".swift", ".kt", ".kts",
    ".go",
}

# Directories to skip (build artifacts, dependencies, cached files)
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next",
    "__pycache__", ".venv", "venv", "vendor",
    ".build", ".gradle", "Pods", "reports", "archive",
}

# Max file size to scan (1 MB) - avoids processing minified bundles
MAX_FILE_SIZE = 1_048_576


# ====================================================================
# THREAT INTELLIGENCE: Known Indicators of Compromise (IOCs)
#
# These IOCs are sourced from published security research reports.
# Each entry includes a justification comment explaining its origin.
# ====================================================================

# Known malicious IPs observed in OpenClaw/ClawHub attack campaigns.
# Sources:
#   - Feb 2026 security advisory on ClawHavoc campaign (~900 malicious skills)
#   - Independent security researcher reports on reverse shell endpoints
KNOWN_MALICIOUS_IPS = [
    # C2 server used by ClawHavoc campaign to host droppers.
    # Observed in base64-decoded payloads from malicious skills.
    # Source: Feb 2026 enterprise security advisory on OpenClaw exploitation.
    ("91.92.242.30", "C2 server used in ClawHavoc campaign to host dropper payloads"),
    # Adjacent infrastructure on same /24 block as 91.92.242.30.
    ("91.92.242.31", "Adjacent C2 infrastructure in same network block as .30"),
    # Reverse shell callback endpoint used by AuthTool malicious skill.
    # Activated when user triggers specific prompts (e.g. Polymarket queries).
    # Source: Feb 2026 enterprise security advisory, AuthTool campaign analysis.
    ("54.91.154.110", "Reverse shell callback endpoint (AuthTool campaign, port 13338)"),
    # Frequently observed in commodity malware C2 infrastructure.
    # Source: Multiple threat intelligence feeds (OTX, VirusTotal).
    ("185.215.113.", "IP range frequently observed in commodity malware C2"),
    # Frequently observed in commodity malware C2 infrastructure.
    ("45.155.205.", "IP range frequently observed in commodity malware C2"),
]

# Known malicious domains used for data exfiltration in ClawHub attacks.
# Source: Feb 2026 enterprise security advisory IOC list.
KNOWN_MALICIOUS_DOMAINS = [
    # Used as exfiltration endpoint in ClawHavoc campaign.
    # Stolen credentials and env vars were POST'd to this API.
    ("socifiapp.com", "Exfiltration endpoint used in ClawHavoc campaign for stolen credentials"),
    # Specific webhook instance used for credential theft.
    # webhook.site is a legitimate service but this specific ID was malicious.
    ("webhook.site/358866c4", "Specific malicious webhook instance used for credential theft"),
]


class SourceCodeScanner:
    """Scans source code for malicious patterns."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings: List[Dict[str, Any]] = []
        self.files_scanned = 0

    def scan(self) -> List[Dict[str, Any]]:
        """Run all source code scans."""
        self.findings = []
        self.files_scanned = 0

        for file_path in self._iter_files():
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            self.files_scanned += 1
            rel_path = str(file_path.relative_to(self.repo_path))

            is_doc = file_path.suffix.lower() in {".md", ".mdx"}
            is_test = any(t in rel_path.lower() for t in [
                ".test.", ".spec.", "__test__", "/test/", "\\test\\",
            ])

            self._scan_base64_payloads(content, rel_path)
            self._scan_malicious_ips(content, rel_path)
            self._scan_malicious_domains(content, rel_path)
            self._scan_credential_harvesting(content, rel_path)
            self._scan_clawdbot_env_access(content, rel_path)
            if not is_test:
                self._scan_obfuscation(content, rel_path)
            if not is_test:
                self._scan_suspicious_network(content, rel_path)
            if not is_doc and not is_test:
                self._scan_dangerous_commands(content, rel_path)
                self._scan_gatekeeper_bypass(content, rel_path)
            self._scan_paste_services(content, rel_path)
            if not is_test:
                self._scan_crypto_wallet_access(content, rel_path)
            if not is_doc and not is_test:
                self._scan_ssrf_patterns(content, rel_path)
                self._scan_path_traversal(content, rel_path)
                self._scan_library_injection(content, rel_path)
                self._scan_crypto_mining(content, rel_path)

        return self.findings

    def _iter_files(self):
        """Iterate over scannable files in the repo."""
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    try:
                        if fpath.stat().st_size <= MAX_FILE_SIZE:
                            yield fpath
                    except OSError:
                        continue

    def _scan_base64_payloads(self, content: str, file_path: str):
        """
        Detect suspicious Base64 encoded strings.

        Why: Malicious OpenClaw skills use Base64-encoded payloads to hide
        shell commands (curl to C2, chmod+execute dropper patterns).
        The decoded payload typically fetches and executes a second-stage
        payload. Example from published research:
          echo 'L2Jpbi9iYXN...' | base64 -D | bash
        which decodes to a curl command fetching from 91.92.242.30.
        """
        b64_pattern = re.compile(
            r'(?:atob|btoa|base64\.b64decode|base64\.decode|Buffer\.from)\s*\(\s*[\'"]([A-Za-z0-9+/=]{40,})[\'"]',
            re.MULTILINE,
        )

        for match in b64_pattern.finditer(content):
            b64_str = match.group(1)
            decoded = self._try_decode_base64(b64_str)
            line_num = content[:match.start()].count("\n") + 1

            severity = "medium"
            desc = f"Base64 encoded string found ({len(b64_str)} chars)"
            if decoded:
                # These keywords in decoded content indicate command execution
                suspicious_keywords = [
                    "curl", "wget", "chmod", "eval", "exec",
                    "/bin/sh", "/bin/bash", "powershell",
                    "http://", "https://", "ftp://",
                ]
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    severity = "critical"
                    desc = f"Base64 encoded command detected: {decoded[:100]}..."

            self.findings.append({
                "type": "source_code",
                "category": "base64_payload",
                "severity": severity,
                "title": "Base64 encoded payload detected",
                "description": desc,
                "file": file_path,
                "line": line_num,
                "reason": "Base64 payloads are the primary delivery mechanism in ClawHavoc campaign malicious skills",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            })

        # Shell scripts: echo <b64> | base64 -d | bash pattern
        if file_path.endswith((".sh", ".bash", ".zsh")):
            raw_b64 = re.findall(r'echo\s+[\'"]?([A-Za-z0-9+/=]{60,})[\'"]?\s*\|\s*base64\s+-d', content)
            for b64_str in raw_b64:
                decoded = self._try_decode_base64(b64_str)
                self.findings.append({
                    "type": "source_code",
                    "category": "base64_payload",
                    "severity": "critical",
                    "title": "Shell Base64 decode pipeline",
                    "description": f"Base64 decoded via pipe in shell script. Decoded: {decoded[:100] if decoded else 'unable to decode'}",
                    "file": file_path,
                    "reason": "echo|base64 -d|bash is the exact pattern used by ClawHavoc dropper payloads",
                    "references": ["https://attack.mitre.org/techniques/T1027/"],
                })

    def _try_decode_base64(self, s: str) -> str | None:
        """Attempt to decode a base64 string."""
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
            if len(decoded) > 5 and any(c.isalpha() for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    def _scan_malicious_ips(self, content: str, file_path: str):
        """
        Detect known malicious IP addresses from published threat intelligence.
        Each IP is documented with its source and campaign attribution above.
        """
        for ip, desc in KNOWN_MALICIOUS_IPS:
            if ip in content:
                line_num = content[:content.index(ip)].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "malicious_ip",
                    "severity": "critical",
                    "title": f"Known malicious IP: {ip}",
                    "description": desc,
                    "file": file_path,
                    "line": line_num,
                    "reason": "IP identified in published security research on OpenClaw exploitation campaigns (Feb 2026)",
                    "references": ["https://attack.mitre.org/techniques/T1071/001/"],
                })

    def _scan_malicious_domains(self, content: str, file_path: str):
        """
        Detect known malicious domains from published IOC lists.
        Each domain is documented with its campaign attribution above.
        """
        for domain, desc in KNOWN_MALICIOUS_DOMAINS:
            if domain in content:
                line_num = content[:content.index(domain)].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "malicious_domain",
                    "severity": "critical",
                    "title": f"Known malicious domain: {domain}",
                    "description": desc,
                    "file": file_path,
                    "line": line_num,
                    "reason": "Domain identified in published IOC list from enterprise security advisory (Feb 2026)",
                    "references": ["https://attack.mitre.org/techniques/T1071/001/"],
                })

    def _scan_gatekeeper_bypass(self, content: str, file_path: str):
        """
        Detect macOS Gatekeeper bypass patterns.

        Why: The AMOS Stealer delivery chain uses xattr -c to strip
        quarantine attributes from downloaded binaries, bypassing macOS
        Gatekeeper checks. This was observed in malicious ClawHub skills
        targeting macOS users. Detection rule: PHASR.Xattr.AttributesCleared.
        """
        patterns = [
            {
                # xattr -c/-r/-d strips extended attributes including
                # com.apple.quarantine which triggers Gatekeeper
                "regex": r"xattr\s+-[crd]",
                "title": "macOS Gatekeeper bypass (xattr clear)",
                "severity": "critical",
                "desc": (
                    "xattr attribute clearing bypasses macOS Gatekeeper quarantine. "
                    "This is the delivery pattern used by AMOS Stealer in malicious "
                    "ClawHub skills. Detection rule: PHASR.Xattr.AttributesCleared."
                ),
                "references": ["https://attack.mitre.org/techniques/T1553/001/"],
            },
            {
                # Disables Gatekeeper system-wide - extremely dangerous
                "regex": r"spctl\s+--master-disable",
                "title": "macOS Gatekeeper disabled system-wide",
                "severity": "critical",
                "desc": "spctl --master-disable turns off Gatekeeper entirely, allowing any unsigned binary to run",
                "references": ["https://attack.mitre.org/techniques/T1553/001/"],
            },
        ]
        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "gatekeeper_bypass",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "reason": "Gatekeeper bypass is a known AMOS Stealer delivery technique observed in ClawHub attacks",
                    "references": pattern.get("references", []),
                })

    def _scan_clawdbot_env_access(self, content: str, file_path: str):
        """
        Detect access to .clawdbot/.env credential file.

        Why: ~/.clawdbot/.env stores API keys (OpenAI, Anthropic, AWS) in
        plaintext. This file is the #1 credential exfiltration target in
        observed attack campaigns against OpenClaw users. Malicious skills
        use JavaScript payloads to read and POST this file to C2 servers.
        """
        patterns = [
            r"\.clawdbot/\.env",       # Unix path
            r"\.clawdbot\\\.env",       # Windows path
            r"CLAWDBOT_HOME.*\.env",    # Via environment variable
            r"OPENCLAW_HOME.*\.env",    # Rebranded name
        ]
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE):
                line_num = content[:re.search(pat, content, re.IGNORECASE).start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "credential_theft",
                    "severity": "critical",
                    "title": "Access to .clawdbot/.env credentials file",
                    "description": (
                        "Direct access to ~/.clawdbot/.env which stores API keys "
                        "(OpenAI, Anthropic, AWS) in plaintext. This is the primary "
                        "credential exfiltration target in observed attack campaigns."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "reason": "~/.clawdbot/.env is the #1 exfiltration target per published enterprise security advisory",
                    "references": ["https://attack.mitre.org/techniques/T1552/001/"],
                })

    def _scan_credential_harvesting(self, content: str, file_path: str):
        """
        Detect credential harvesting patterns.

        Why: Malicious ClawHub skills specifically target crypto wallet
        credentials (Solana, Phantom, Polymarket) and cloud API keys.
        These env var names appear in published IOC lists from the
        ClawHavoc campaign analysis.
        """
        patterns = [
            {
                # Solana wallet credentials - targeted by crypto-stealing skills
                # Source: ClawHavoc campaign IOC list, solana-9lplb malicious skill
                "regex": r"SOLANA_KEYPAIR_PATH|SOLANA_PRIVATE_KEY|SOL_PRIVATE",
                "title": "Solana credential access",
                "severity": "critical",
                "desc": "Access to Solana wallet credentials - targeted by known malicious skills (e.g. solana-9lplb)",
            },
            {
                # Polymarket API keys - targeted by polymarket-7ceau malicious skill
                # Source: ClawHavoc campaign IOC list
                "regex": r"POLYMARKET_API_KEY|POLYMARKET_SECRET",
                "title": "Polymarket credential access",
                "severity": "critical",
                "desc": "Access to Polymarket API credentials - targeted by known malicious skills (e.g. polymarket-7ceau)",
            },
            {
                # Phantom wallet - targeted by phantom-0jcvy malicious skill
                # Source: ClawHavoc campaign IOC list
                "regex": r"PHANTOM_WALLET|PHANTOM_PRIVATE|phantom.*(?:key|secret|wallet)",
                "title": "Phantom wallet access",
                "severity": "critical",
                "desc": "Access to Phantom wallet credentials - targeted by known malicious skills (e.g. phantom-0jcvy)",
            },
            {
                # AWS credentials hardcoded - standard OWASP finding
                "regex": r"(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[=:]",
                "title": "AWS credential hardcoded",
                "severity": "high",
                "desc": "Hardcoded AWS credentials found (OWASP A07:2021 - Security Misconfiguration)",
            },
            {
                # Generic private key assignment - standard OWASP finding
                "regex": r"(?:PRIVATE_KEY|PRIVATE[-_]?KEY)\s*[=:]\s*['\"](?!\.)",
                "title": "Hardcoded private key",
                "severity": "high",
                "desc": "Hardcoded private key value detected (OWASP A07:2021)",
            },
            {
                # Hardcoded password with 8+ chars - standard OWASP finding
                "regex": r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                "title": "Hardcoded password",
                "severity": "high",
                "desc": "Hardcoded password detected (OWASP A07:2021 - Security Misconfiguration)",
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                # Skip test files, docs, and config templates (expected to mention these)
                if any(skip in file_path.lower() for skip in [
                    "test", ".md", "readme", "example", "template",
                    ".env.example", "mock", "fixture",
                ]):
                    continue
                self.findings.append({
                    "type": "source_code",
                    "category": "credential_harvesting",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://attack.mitre.org/techniques/T1552/001/"],
                })

    def _scan_obfuscation(self, content: str, file_path: str):
        """
        Detect code obfuscation patterns.

        Why: Malicious skills use obfuscation to evade detection.
        Common patterns: eval(atob(...)) for Base64 decoding,
        Function constructor for dynamic code gen, hex/unicode
        escape sequences to hide strings. Published detection rules:
        PHASR.Base64.Decode, EDR.DeobfuscateFilesOrInformation.
        """
        patterns = [
            {
                # eval() + decoding function = classic malware deobfuscation
                "regex": r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)",
                "title": "Obfuscated eval() call",
                "severity": "critical",
                "desc": "eval() with encoding/decoding function - classic malware deobfuscation pattern",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
            {
                # eval() with string literal = dynamic code execution
                "regex": r"\beval\s*\(\s*['\"]",
                "title": "eval() with string argument",
                "severity": "high",
                "desc": "Dynamic code execution via eval() with string literal",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
            {
                # Function() constructor bypasses CSP and static analysis
                "regex": r"Function\s*\(\s*['\"](?:return|var|let|const)",
                "title": "Dynamic Function constructor",
                "severity": "high",
                "desc": "Dynamic code generation via Function constructor - bypasses static analysis",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
            {
                # 10+ consecutive hex escapes suggest obfuscated payload
                "regex": r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}",
                "title": "Hex-encoded string sequence",
                "severity": "medium",
                "desc": "Long hex-encoded string (10+ chars) - possible obfuscated payload",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
            {
                # 10+ consecutive unicode escapes suggest obfuscated payload
                "regex": r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}",
                "title": "Unicode-escaped string sequence",
                "severity": "medium",
                "desc": "Long unicode-escaped string (10+ chars) - possible obfuscated payload",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
            {
                # Python exec() with dynamic imports = runtime code loading
                "regex": r"exec\s*\(\s*(?:compile|__import__|globals|getattr)",
                "title": "Python exec with dynamic import",
                "severity": "critical",
                "desc": "Python exec() with dynamic code loading - used in AuthTool campaign reverse shells",
                "references": ["https://attack.mitre.org/techniques/T1027/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                if any(skip in file_path.lower() for skip in ["test", "mock", "fixture", "spec"]):
                    continue
                self.findings.append({
                    "type": "source_code",
                    "category": "obfuscation",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "match": match.group(0)[:120],
                    "references": pattern.get("references", []),
                })

    def _scan_suspicious_network(self, content: str, file_path: str):
        """
        Detect suspicious outbound network calls.

        Why: Malicious skills use direct IP connections (not domains) to
        avoid DNS-based blocking and make C2 traffic harder to attribute.
        """
        patterns = [
            {
                # HTTP to raw IP = bypasses domain-based security controls
                "regex": r"(?:fetch|axios|request|http\.get|https\.get|urllib)\s*\(\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}",
                "title": "HTTP request to raw IP address",
                "severity": "high",
                "desc": "Network request to raw IP address instead of domain - bypasses DNS-based security controls",
                "references": ["https://attack.mitre.org/techniques/T1071/001/"],
            },
            {
                # Function names suggesting data theft
                "regex": r"(?:XMLHttpRequest|fetch)\s*\(.*?(?:exfil|steal|harvest|keylog)",
                "title": "Suspicious data exfiltration pattern",
                "severity": "critical",
                "desc": "Network call with exfiltration-related naming",
                "references": ["https://attack.mitre.org/techniques/T1071/001/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "suspicious_network",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "references": pattern.get("references", []),
                })

    def _scan_dangerous_commands(self, content: str, file_path: str):
        """
        Detect dangerous shell command patterns.

        Why: curl|bash is the primary initial access technique in ClawHub
        attacks. Malicious SKILL.md files instruct users to run obfuscated
        install commands that pipe remote content directly to shell.
        Detection rule: PHASR.Curl.Silent.
        """
        patterns = [
            {
                # curl|bash = download and execute, MITRE ATT&CK T1059.004
                "regex": r"(?:curl|wget)\s+.*?\|\s*(?:bash|sh|zsh|python|perl|ruby)",
                "title": "Remote code execution via pipe",
                "severity": "critical",
                "desc": "Download and execute pattern (curl|bash) - MITRE ATT&CK T1059.004",
                "references": ["https://attack.mitre.org/techniques/T1059/004/"],
            },
            {
                # chmod+execute = dropper pattern, MITRE ATT&CK T1204.002
                "regex": r"chmod\s+(?:\+x|777|755)\s+.*?&&\s*\./",
                "title": "Download, chmod, execute pattern",
                "severity": "critical",
                "desc": "File made executable and immediately run - dropper pattern (MITRE ATT&CK T1204.002)",
                "references": ["https://attack.mitre.org/techniques/T1204/002/"],
            },
            {
                # rm -rf system dirs = destructive action, MITRE ATT&CK T1485
                "regex": r"rm\s+-rf\s+(?:/(?:etc|usr|var|home|root)|~|\$HOME)",
                "title": "Destructive rm -rf command",
                "severity": "critical",
                "desc": "Destructive deletion of system directories (MITRE ATT&CK T1485)",
                "references": ["https://attack.mitre.org/techniques/T1485/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                # Install/setup scripts legitimately use curl|bash
                is_install_script = any(
                    kw in file_path.lower()
                    for kw in ["install", "setup", "bootstrap", "init"]
                )
                severity = "medium" if is_install_script else pattern["severity"]
                self.findings.append({
                    "type": "source_code",
                    "category": "dangerous_command",
                    "severity": severity,
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "match": match.group(0)[:120],
                    "references": pattern.get("references", []),
                })

    def _scan_paste_services(self, content: str, file_path: str):
        """
        Detect usage of paste services for payload hosting.

        Why: Malicious skills use paste services (glot.io, pastebin.com)
        to host second-stage payloads. The skill downloads from these
        services at runtime, making the payload harder to detect by
        static analysis of the skill code itself.
        """
        # These services are commonly abused for malware hosting
        paste_domains = [
            "glot.io",       # Used in observed ClawHub malicious skills
            "pastebin.com",  # Widely abused for malware hosting
            "paste.ee",      # Alternative paste service
            "hastebin.com",  # Alternative paste service
            "ghostbin.co",   # Anonymous paste service
            "rentry.co",     # Markdown paste service
            "dpaste.org",    # Developer paste service
            "ix.io",         # Curl-friendly paste service
            "sprunge.us",    # Curl-friendly paste service
            "0x0.st",        # File hosting often used for payloads
        ]

        for domain in paste_domains:
            if domain in content:
                line_num = content[:content.index(domain)].count("\n") + 1
                if file_path.endswith((".md", ".mdx")):
                    continue
                self.findings.append({
                    "type": "source_code",
                    "category": "paste_service",
                    "severity": "medium",
                    "title": f"Paste service reference: {domain}",
                    "description": f"Reference to paste service {domain} - commonly used for hosting malicious payloads in skill attacks",
                    "file": file_path,
                    "line": line_num,
                    "references": ["https://attack.mitre.org/techniques/T1102/"],
                })

    def _scan_crypto_wallet_access(self, content: str, file_path: str):
        """
        Detect cryptocurrency wallet file access patterns.

        Why: Crypto wallet theft is the primary financial motivation in
        ClawHub attacks. Known malicious skills (solana-9lplb, phantom-0jcvy)
        specifically target wallet files. Skills run with full local
        privileges, meaning direct file access to wallet keystores is trivial.
        """
        patterns = [
            {
                # Solana wallet files - targeted by solana-9lplb
                "regex": r"\.solana/id\.json|solana.*keypair|sol.*(?:private|secret).*key",
                "title": "Solana wallet file access",
                "severity": "critical",
                "desc": "Direct access to Solana wallet files - matches known malicious skill targeting pattern",
                "references": ["https://attack.mitre.org/techniques/T1552/001/"],
            },
            {
                # Ethereum keystore - standard crypto wallet target
                "regex": r"\.ethereum/keystore|\.eth/.*key",
                "title": "Ethereum keystore access",
                "severity": "critical",
                "desc": "Direct access to Ethereum keystore files",
                "references": ["https://attack.mitre.org/techniques/T1552/001/"],
            },
            {
                # Bitcoin wallet.dat - standard crypto wallet target
                "regex": r"wallet\.dat|\.bitcoin/wallet",
                "title": "Bitcoin wallet access",
                "severity": "critical",
                "desc": "Direct access to Bitcoin wallet files",
                "references": ["https://attack.mitre.org/techniques/T1552/001/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                if any(skip in file_path.lower() for skip in ["test", ".md", "readme", "doc"]):
                    continue
                self.findings.append({
                    "type": "source_code",
                    "category": "crypto_wallet",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "references": pattern.get("references", []),
                })

    def _scan_ssrf_patterns(self, content: str, file_path: str):
        """
        Detect Server-Side Request Forgery (SSRF) patterns.

        Why: OpenClaw had to patch SSRF vulnerabilities in skill installer
        downloads and remote media fetches (with DNS pinning). Malicious
        skills can reference private/internal network addresses to access
        cloud metadata endpoints (169.254.169.254) or internal services.
        """
        # Skip SSRF protection/guard files (they contain these patterns as blocklists)
        if any(skip in file_path.lower() for skip in [
            "ssrf", "security/", "security\\", "guard", "block",
        ]):
            return

        patterns = [
            {
                # AWS/cloud metadata endpoint - SSRF to steal IAM credentials
                "regex": r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
                "title": "Cloud metadata endpoint access",
                "severity": "critical",
                "desc": "Reference to cloud instance metadata endpoint - SSRF can steal IAM credentials and secrets",
                "reason": "OpenClaw patched SSRF guards for skill downloads; metadata access enables cloud account takeover",
                "references": ["https://cwe.mitre.org/data/definitions/918.html"],
            },
            {
                # Fetch/request to localhost or 127.x - internal service access
                "regex": r"(?:fetch|request|axios|http\.get|urllib)\s*\(\s*['\"]https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
                "title": "Request to localhost/loopback",
                "severity": "high",
                "desc": "Network request targeting localhost - may access internal services or exploit auto-approve bypass",
                "reason": "OpenClaw auto-approves localhost connections; SSRF to 127.0.0.1 bypasses all authentication",
                "references": ["https://cwe.mitre.org/data/definitions/918.html"],
            },
            {
                # Private IP ranges in URLs - NIST SP 800-53 SA-12
                "regex": r"(?:fetch|request|axios|http\.get|urllib)\s*\(\s*['\"]https?://(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
                "title": "Request to private network address",
                "severity": "high",
                "desc": "Network request to RFC1918 private address range - potential SSRF to internal infrastructure",
                "reason": "Skills should not access internal network resources; this pattern enables lateral movement",
                "references": ["https://cwe.mitre.org/data/definitions/918.html"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "ssrf",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "reason": pattern.get("reason", ""),
                    "references": pattern.get("references", []),
                })

    def _scan_path_traversal(self, content: str, file_path: str):
        """
        Detect path traversal patterns.

        Why: OpenClaw had multiple security fixes for path traversal
        (PR #4610, #4930, #6398) in message attachments, media paths,
        and skill sandboxes. Path traversal allows reading arbitrary
        files outside the skill's working directory, including
        credentials and system files.
        """
        patterns = [
            {
                # readFile/readFileSync with ../ concatenation
                "regex": r"(?:readFile|readFileSync|readdir|open)\s*\([^)]*\.\.(?:/|\\\\)",
                "title": "File read with path traversal",
                "severity": "high",
                "desc": "File operation using ../ path traversal - may escape skill sandbox to access system files",
                "reason": "OpenClaw patched path traversal in PRs #4610, #4930, #6398 after exploitation in production",
                "references": ["https://cwe.mitre.org/data/definitions/22.html"],
            },
            {
                # Dynamic path construction with user input + ../
                "regex": r"path\.(?:join|resolve)\s*\([^)]*\.\.\s*[,)]",
                "title": "Dynamic path with parent traversal",
                "severity": "high",
                "desc": "Path.join/resolve called with '..' component - potential sandbox escape via path manipulation",
                "reason": "GHSA-4mhr-g7xj-cg8j: Lobster extension exploited via path parameter injection",
                "references": ["https://cwe.mitre.org/data/definitions/22.html"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                if any(skip in file_path.lower() for skip in ["test", "spec", "mock"]):
                    continue
                self.findings.append({
                    "type": "source_code",
                    "category": "path_traversal",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "reason": pattern.get("reason", ""),
                    "references": pattern.get("references", []),
                })

    def _scan_library_injection(self, content: str, file_path: str):
        """
        Detect LD_PRELOAD / DYLD library injection patterns.

        Why: OpenClaw had to block LD_PRELOAD and DYLD_INSERT_LIBRARIES
        environment variable overrides for host exec (fix #4896). These
        allow intercepting system library calls to inject malicious code
        into any process. MITRE ATT&CK T1574.006.
        """
        patterns = [
            {
                # LD_PRELOAD - Linux library injection
                "regex": r"LD_PRELOAD\s*=|LD_LIBRARY_PATH\s*=",
                "title": "LD_PRELOAD library injection",
                "severity": "critical",
                "desc": "Setting LD_PRELOAD enables injecting malicious shared libraries into any process (MITRE ATT&CK T1574.006)",
                "reason": "OpenClaw blocked LD_PRELOAD in fix #4896 after it was identified as a sandbox escape vector",
                "references": ["https://attack.mitre.org/techniques/T1574/006/"],
            },
            {
                # DYLD_INSERT_LIBRARIES - macOS library injection
                "regex": r"DYLD_INSERT_LIBRARIES\s*=|DYLD_LIBRARY_PATH\s*=|DYLD_FRAMEWORK_PATH\s*=",
                "title": "DYLD library injection (macOS)",
                "severity": "critical",
                "desc": "Setting DYLD_INSERT_LIBRARIES enables injecting malicious dylibs into any macOS process",
                "reason": "macOS equivalent of LD_PRELOAD; blocked in OpenClaw fix #4896 as a sandbox escape vector",
                "references": ["https://attack.mitre.org/techniques/T1574/006/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "library_injection",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "reason": pattern.get("reason", ""),
                    "references": pattern.get("references", []),
                })

    def _scan_crypto_mining(self, content: str, file_path: str):
        """
        Detect cryptocurrency mining indicators.

        Why: OpenClaw's built-in security audit checks for crypto mining
        patterns (stratum+tcp, coinhive, xmrig) as critical severity.
        Resource hijacking via AI agent skills is a known monetization
        strategy. MITRE ATT&CK T1496.
        """
        # Skip security scanner files that contain these patterns as detection rules
        if any(skip in file_path.lower() for skip in [
            "security/", "security\\", "scanner", "audit", "detect",
        ]):
            return

        patterns = [
            {
                # Stratum mining protocol - universal mining pool connection
                "regex": r"stratum\+tcp://|stratum\+ssl://",
                "title": "Mining pool protocol detected",
                "severity": "critical",
                "desc": "Stratum mining protocol reference - indicates cryptocurrency mining payload (MITRE ATT&CK T1496)",
                "references": ["https://attack.mitre.org/techniques/T1496/"],
            },
            {
                # Known mining software names
                "regex": r"\b(?:xmrig|coinhive|coin-hive|minergate|cryptonight|moneroocean)\b",
                "title": "Crypto mining software reference",
                "severity": "critical",
                "desc": "Reference to known cryptocurrency mining software - resource hijacking indicator",
                "references": ["https://attack.mitre.org/techniques/T1496/"],
            },
            {
                # WebAssembly-based browser miners
                "regex": r"(?:CoinHive|CryptoLoot|deepMiner|AuthedMine)\s*\.\s*(?:Anonymous|User|Token)",
                "title": "Browser-based crypto miner",
                "severity": "critical",
                "desc": "WebAssembly/JavaScript-based browser crypto miner detected",
                "references": ["https://attack.mitre.org/techniques/T1496/"],
            },
        ]

        for pattern in patterns:
            for match in re.finditer(pattern["regex"], content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append({
                    "type": "source_code",
                    "category": "crypto_mining",
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "description": pattern["desc"],
                    "file": file_path,
                    "line": line_num,
                    "reason": "OpenClaw's built-in scanner flags crypto mining as critical; MITRE ATT&CK T1496 Resource Hijacking",
                    "references": pattern.get("references", []),
                })
