"""
Skill Scanner - Analyzes OpenClaw skills for malicious behavior.
Parses SKILL.md files, checks referenced scripts, and identifies
suspicious skill patterns. Each finding includes verifiable references.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any


class SkillScanner:
    """Scans OpenClaw skills directory for threats."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.skills_dir = self.repo_path / "skills"
        self.findings: List[Dict[str, Any]] = []
        self.skills_scanned = 0
        self.skill_metadata: List[Dict[str, Any]] = []

    def scan(self) -> List[Dict[str, Any]]:
        """Scan all skills in the repository."""
        self.findings = []
        self.skills_scanned = 0
        self.skill_metadata = []

        if not self.skills_dir.exists():
            # Check for skills in other locations
            alt_paths = [
                self.repo_path / ".agents" / "skills",
                self.repo_path / "extensions",
            ]
            for alt in alt_paths:
                if alt.exists():
                    self._scan_skills_in_dir(alt)
            return self.findings

        self._scan_skills_in_dir(self.skills_dir)

        # Also scan extension skills
        extensions_dir = self.repo_path / "extensions"
        if extensions_dir.exists():
            self._scan_extension_skills(extensions_dir)

        # Agent skills
        agent_skills_dir = self.repo_path / ".agents" / "skills"
        if agent_skills_dir.exists():
            self._scan_skills_in_dir(agent_skills_dir)

        return self.findings

    def _scan_skills_in_dir(self, skills_dir: Path):
        """Scan all skills in a given directory."""
        for item in skills_dir.iterdir():
            if item.is_dir():
                skill_md = item / "SKILL.md"
                if skill_md.exists():
                    self._analyze_skill(item, skill_md)
                    self.skills_scanned += 1

    def _scan_extension_skills(self, extensions_dir: Path):
        """Scan skills embedded in extensions."""
        for ext_dir in extensions_dir.iterdir():
            if ext_dir.is_dir():
                ext_skills = ext_dir / "skills"
                if ext_skills.exists():
                    self._scan_skills_in_dir(ext_skills)
                # Some extensions have SKILL.md at root
                skill_md = ext_dir / "SKILL.md"
                if skill_md.exists():
                    self._analyze_skill(ext_dir, skill_md)
                    self.skills_scanned += 1

    def _analyze_skill(self, skill_dir: Path, skill_md: Path):
        """Analyze a single skill for malicious patterns."""
        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        rel_dir = str(skill_dir.relative_to(self.repo_path))
        skill_name = skill_dir.name

        # Extract metadata
        metadata = {
            "name": skill_name,
            "path": rel_dir,
            "has_scripts": False,
            "referenced_tools": [],
            "permissions_requested": [],
        }

        # Check for suspicious skill names (random suffix like -7ceau, -0jcvy)
        # Must contain mixed letters+digits to look truly random
        random_suffix = re.search(r"-([a-z0-9]{4,6})$", skill_name)
        if random_suffix and re.search(r"[a-z]", random_suffix.group(1)) and re.search(r"[0-9]", random_suffix.group(1)):
            self.findings.append({
                "type": "skill",
                "category": "suspicious_name",
                "severity": "medium",
                "title": f"Skill with random suffix: {skill_name}",
                "description": (
                    f"Skill '{skill_name}' has a random-looking suffix "
                    f"({random_suffix.group(0)}). Mass-published malicious skills "
                    "often use random suffixes to avoid name collisions."
                ),
                "file": f"{rel_dir}/SKILL.md",
                "references": [
                    "https://attack.mitre.org/techniques/T1036/",
                ],
            })

        # Check SKILL.md content for dangerous patterns
        self._check_skill_content(content, rel_dir, skill_name)

        # Scan all files in the skill directory
        self._scan_skill_files(skill_dir, rel_dir, skill_name)

        # Check for tool/permission requests
        self._check_permissions(content, rel_dir, skill_name, metadata)

        self.skill_metadata.append(metadata)

    def _check_skill_content(self, content: str, rel_dir: str, skill_name: str):
        """Check SKILL.md content for suspicious patterns."""
        content_lower = content.lower()

        # Check for dangerous tool requests
        dangerous_tools = [
            ("bash", "Shell command execution"),
            ("write", "File write access"),
            ("curl", "Network requests via curl"),
            ("wget", "Network requests via wget"),
        ]

        for tool, desc in dangerous_tools:
            # Look for tool being referenced in capability/tools section
            tool_pattern = re.compile(
                rf"(?:tools?|capabilities?|permissions?)\s*:.*?{tool}",
                re.IGNORECASE | re.DOTALL,
            )
            if tool_pattern.search(content):
                self.findings.append({
                    "type": "skill",
                    "category": "dangerous_permission",
                    "severity": "medium",
                    "title": f"Skill '{skill_name}' requests {tool} access",
                    "description": f"Skill requests {desc} capability. Review carefully.",
                    "file": f"{rel_dir}/SKILL.md",
                    "references": [
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    ],
                })

        # Check for URLs to suspicious domains
        urls = re.findall(r'https?://[^\s\)\"\']+', content)
        suspicious_domains = [
            "glot.io", "pastebin.com", "paste.ee",
            "raw.githubusercontent.com", "gist.github.com",
        ]
        for url in urls:
            for domain in suspicious_domains:
                if domain in url:
                    self.findings.append({
                        "type": "skill",
                        "category": "suspicious_url",
                        "severity": "high",
                        "title": f"Suspicious URL in skill '{skill_name}'",
                        "description": f"Skill references {domain}: {url[:100]}",
                        "file": f"{rel_dir}/SKILL.md",
                        "references": [
                            "https://attack.mitre.org/techniques/T1102/",
                        ],
                    })

        # Check for prompt injection patterns in SKILL.md
        # Why: SKILL.md is read directly by the AI agent as instructions.
        # A crafted SKILL.md can hijack agent behavior, bypass safety
        # controls, or instruct the agent to exfiltrate data.
        # OWASP LLM01 (Prompt Injection), MITRE ATLAS AML.T0051.
        prompt_injection_patterns = [
            {
                "regex": r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|constraints?)",
                "title": "Prompt injection: instruction override",
                "desc": "Attempts to override the agent's system instructions (OWASP LLM01)",
            },
            {
                "regex": r"you\s+are\s+now\s+(?:a|an|the)\s+",
                "title": "Prompt injection: role manipulation",
                "desc": "Attempts to reassign the agent's role/persona to bypass safety controls",
            },
            {
                "regex": r"(?:send|post|upload|transmit)\s+(?:all|every|the)\s+(?:file|content|data|code|secret|key|token|credential)",
                "title": "Prompt injection: data exfiltration instruction",
                "desc": "Instructs the agent to exfiltrate files or credentials",
            },
            {
                "regex": r"(?:do\s+not|don'?t|never)\s+(?:show|tell|reveal|mention|display)\s+(?:the\s+user|anyone)",
                "title": "Prompt injection: concealment instruction",
                "desc": "Instructs the agent to hide its actions from the user",
            },
            {
                "regex": r"(?:run|execute|use)\s+bash\s+(?:to|and)\s+(?:curl|wget|download|install|rm|delete)",
                "title": "Prompt injection: tool abuse instruction",
                "desc": "Instructs the agent to use bash for downloading or destructive operations",
            },
        ]

        for pattern in prompt_injection_patterns:
            if re.search(pattern["regex"], content, re.IGNORECASE):
                self.findings.append({
                    "type": "skill",
                    "category": "prompt_injection",
                    "severity": "critical",
                    "title": f"{pattern['title']} in '{skill_name}'",
                    "description": pattern["desc"],
                    "file": f"{rel_dir}/SKILL.md",
                    "reason": "SKILL.md is executed as agent instructions; prompt injection can hijack agent behavior entirely",
                    "references": [
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "https://atlas.mitre.org/techniques/AML.T0051",
                    ],
                })

        # Check for crypto/financial keywords
        crypto_keywords = [
            "solana", "phantom", "polymarket", "metamask",
            "private.key", "seed.phrase", "mnemonic", "keypair",
            "wallet", "token.transfer", "airdrop",
        ]
        found_crypto = [kw for kw in crypto_keywords if kw.replace(".", " ") in content_lower]
        if len(found_crypto) >= 2:
            self.findings.append({
                "type": "skill",
                "category": "crypto_related",
                "severity": "high",
                "title": f"Crypto-related skill: {skill_name}",
                "description": (
                    f"Skill contains multiple crypto-related keywords: {', '.join(found_crypto)}. "
                    "This matches the pattern of known malicious skills targeting crypto wallets."
                ),
                "file": f"{rel_dir}/SKILL.md",
                "references": [
                    "https://attack.mitre.org/techniques/T1552/001/",
                ],
            })

    def _scan_skill_files(self, skill_dir: Path, rel_dir: str, skill_name: str):
        """Scan all files within a skill directory."""
        skip_dirs = {"node_modules", ".git", "__pycache__"}
        scannable_exts = {".js", ".ts", ".py", ".sh", ".bash", ".mjs"}

        for root, dirs, files in os.walk(skill_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in scannable_exts:
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                file_rel = str(fpath.relative_to(self.repo_path))

                # Check for obfuscated code
                if self._is_obfuscated(content):
                    self.findings.append({
                        "type": "skill",
                        "category": "obfuscated_code",
                        "severity": "critical",
                        "title": f"Obfuscated code in skill '{skill_name}'",
                        "description": f"File {fname} contains obfuscated code patterns",
                        "file": file_rel,
                        "references": [
                            "https://attack.mitre.org/techniques/T1027/",
                        ],
                    })

                # Check for data exfiltration patterns
                exfil_patterns = [
                    r"(?:readFileSync|readFile)\s*\(.*?(?:\.ssh|\.aws|\.solana|\.ethereum)",
                    r"(?:fetch|axios|request)\s*\(.*?(?:webhook|exfil|collect)",
                    r"process\.env\s*\[.*?\].*?(?:fetch|send|post|request)",
                ]
                for pat in exfil_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        self.findings.append({
                            "type": "skill",
                            "category": "data_exfiltration",
                            "severity": "critical",
                            "title": f"Data exfiltration pattern in '{skill_name}'",
                            "description": f"Suspicious data access + network pattern in {fname}",
                            "file": file_rel,
                            "references": [
                                "https://attack.mitre.org/techniques/T1041/",
                                "https://attack.mitre.org/techniques/T1552/001/",
                            ],
                        })

    def _is_obfuscated(self, content: str) -> bool:
        """Check if code appears obfuscated."""
        indicators = 0

        # Very long lines (>500 chars)
        for line in content.split("\n"):
            if len(line) > 500 and not line.strip().startswith("//"):
                indicators += 1

        # High ratio of hex/unicode escapes
        hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
        unicode_count = len(re.findall(r"\\u[0-9a-fA-F]{4}", content))
        if hex_count > 20 or unicode_count > 20:
            indicators += 2

        # Variable names that look random
        random_vars = re.findall(r"\b_0x[a-f0-9]{4,}\b", content)
        if len(random_vars) > 3:
            indicators += 2

        return indicators >= 2

    def _check_permissions(self, content: str, rel_dir: str, skill_name: str, metadata: dict):
        """Extract and evaluate permission requests."""
        # Look for tool specifications
        tool_matches = re.findall(r"(?:tool|command|action)\s*:\s*(\w+)", content, re.IGNORECASE)
        metadata["referenced_tools"] = tool_matches

        # Check for filesystem access patterns
        if re.search(r"(?:read|write|access)\s+(?:file|directory|folder|path)", content, re.IGNORECASE):
            metadata["permissions_requested"].append("filesystem")

        if re.search(r"(?:network|http|fetch|request|api)", content, re.IGNORECASE):
            metadata["permissions_requested"].append("network")
