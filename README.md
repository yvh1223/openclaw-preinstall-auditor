# McAfee OpenClaw Pre-Install Security Auditor

**Static security analysis for the OpenClaw AI agent framework before installation.**

Scans the OpenClaw open-source repository for known CVEs, malicious code patterns, architectural weaknesses, and supply chain risks. Generates a professional HTML report with risk scoring, threat intelligence cards, and collapsible finding details.

## Why Pre-Install Scanning Matters

OpenClaw (formerly Clawdbot/Moltbot) runs with the user's full system privileges. Any compromise of the auth token, gateway, or skill system gives an attacker complete control over the host machine. Published research has identified:

- **~900 malicious skills** on ClawHub (~20% of total marketplace)
- **CVE-2026-25253** - 1-Click RCE via gatewayUrl token exfiltration (CVSS 8.8)
- **CVE-2026-21636** - Node.js Permission Model bypass undermines runtime sandboxing
- **Localhost auto-approve bypass** - reverse proxy deployments silently skip auth
- **Mass-published trojanized skills** impersonating crypto tools (Solana, Phantom, Polymarket)

Norton and VirusTotal provide only shallow URL/hash scanning. This tool performs deep static analysis at the source code level.

## What It Scans

| Scanner | What It Detects |
|---------|----------------|
| **Dependency Scanner** | Known CVEs in npm/pip packages, unpinned versions, vulnerable overrides |
| **Source Code Scanner** | Base64 payloads, malicious IPs/domains, credential harvesting, Gatekeeper bypass, SSRF, path traversal, LD_PRELOAD injection, crypto mining, code obfuscation |
| **Skill Scanner** | Prompt injection in SKILL.md, suspicious skill names, dangerous permissions, crypto keywords, data exfiltration patterns |
| **Vulnerability Scanner** | CVE-2026-25253, CVE-2025-59466, CVE-2026-21636, localhost auto-approve bypass, sandbox escape vectors, npm lifecycle script abuse, SOUL.md exposure, auth token storage |

### Framework Compliance

- **OWASP LLM Top 10** - LLM01 (Prompt Injection), LLM05 (Supply Chain), LLM06 (Sensitive Info Disclosure), LLM07 (Insecure Plugin Design), LLM08 (Excessive Agency)
- **MITRE ATT&CK** - T1059.004, T1204.002, T1485, T1027, T1552.001, T1574.006, T1496, T1195.002, T1553.001
- **MITRE ATLAS** - AML.T0010 (ML Supply Chain Compromise), AML.T0051 (LLM Prompt Injection)
- **NIST SP 800-53** - SA-12 (Supply Chain Protection), SI-3 (Malicious Code Protection), RA-5 (Vulnerability Scanning)

## Quick Start

```bash
# 1. Clone this repo
git clone <repo-url> mcafee_openclaw_auditor
cd mcafee_openclaw_auditor

# 2. Install dependencies (only colorama required)
pip install -r requirements.txt

# 3. Clone the OpenClaw repo to scan
git clone https://github.com/openclaw/openclaw ../openclaw_repo

# 4. Run the scanner
python scripts/scan_and_report.py --repo ../openclaw_repo
```

### Output

The scanner generates three report formats:
- **HTML** - Professional dark-theme report with Chart.js charts, threat intel cards, and collapsible findings
- **JSON** - Machine-readable structured output
- **Text** - CLI-friendly summary (`--text path/to/report.txt`)

Reports are saved to the `reports/` directory with timestamps.

## Project Structure

```
mcafee_openclaw_auditor/
|-- scripts/
|   `-- scan_and_report.py             # Main entry point (4-phase scanner)
|-- src/
|   |-- scanners/
|   |   |-- dependency_scanner.py      # npm/pip CVE scanning
|   |   |-- source_code_scanner.py     # 15 malicious pattern categories
|   |   |-- skill_scanner.py           # SKILL.md + skill directory analysis
|   |   `-- vulnerability_scanner.py   # CVE + architecture weakness checks
|   |-- analyzers/
|   |   `-- risk_scorer.py             # Weighted 0-100 risk scoring
|   `-- utils/
|       `-- report_generator.py        # HTML/JSON/text report generation
|-- reports/                           # Generated scan reports
|-- requirements.txt                   # Dependencies (colorama only)
`-- archive/                           # Old files kept for reference
```

## Scan Results

Typical scan of the OpenClaw repository:

```
Risk Score:      100/100 (CRITICAL)
Total Findings:  53+
  Critical: 5    (CVE-2026-25253, Gatekeeper bypass, auth bypass, sandbox escape)
  High:     20+  (credential harvesting, dangerous configs, dependency CVEs)
  Medium:   27+  (unpinned deps, config weaknesses, npm lifecycle scripts)
Scan Time:       ~13s
Files Scanned:   4,664
Skills Analyzed: 61
```

## IOCs (Indicators of Compromise)

| Type | Indicator | Context |
|------|-----------|---------|
| IP | 91.92.242.30 | C2 server, dropper payload hosting |
| IP | 54.91.154.110:13338 | Reverse shell callback endpoint |
| Domain | socifiapp.com | Credential exfiltration endpoint |
| Domain | webhook.site/358866c4 | Malicious webhook for credential theft |
| File | ~/.clawdbot/.env | Primary credential exfiltration target |
| Env Var | SOLANA_KEYPAIR_PATH | Crypto wallet theft target |

## How It Works

The scanner runs 4 phases sequentially:

1. **Dependency Scan** - Parses package.json/requirements.txt, checks against known CVE database, flags unpinned versions
2. **Source Code Scan** - Walks all source files (4,600+), applies 15 regex-based pattern categories with context-aware severity
3. **Skill Scan** - Analyzes 60+ skills' SKILL.md files and code directories for prompt injection, exfiltration, and suspicious patterns
4. **Vulnerability Scan** - Checks specific files for known CVE-vulnerable code patterns, dangerous config defaults, and architectural weaknesses

All findings are scored using a weighted system (Critical=40, High=20, Medium=10, Low=5) and capped at 100.

## Requirements

- Python 3.9+
- `colorama` (for colored terminal output)
- No external security tools required - all scanning is built-in via regex pattern matching

## License

McAfee Internal - Proof of Concept
