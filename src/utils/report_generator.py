"""
Report Generator - Produces HTML, JSON, and text reports.
HTML report includes charts, severity breakdowns, collapsible findings,
and threat intelligence cards with enriched details.
"""

import json
import html
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Dict, Any, List


class ReportGenerator:
    """Generates professional security audit reports."""

    def __init__(self, scan_results: Dict[str, Any], report_profile: str = "full"):
        self.results = scan_results
        self.generated_at = datetime.now().isoformat()
        profile = (report_profile or "full").strip().lower()
        self.report_profile = profile if profile in {"full", "concise"} else "full"

    def save_html(self, output_path: str):
        """Generate and save an HTML report."""
        html_content = self._build_html()
        Path(output_path).write_text(html_content, encoding="utf-8")

    def save_json(self, output_path: str):
        """Save results as JSON."""
        Path(output_path).write_text(
            json.dumps(self.results, indent=2, default=str),
            encoding="utf-8",
        )

    def save_text(self, output_path: str):
        """Save a text summary."""
        text = self._build_text()
        Path(output_path).write_text(text, encoding="utf-8")

    def _build_html(self) -> str:
        """Build the complete HTML report."""
        risk = self.results.get("risk_summary", {})
        findings = self.results.get("findings", [])
        meta = self.results.get("scan_metadata", {})
        is_concise = self.report_profile == "concise"

        score = risk.get("risk_score", 0)
        level = risk.get("risk_level", "UNKNOWN")
        recommendation = risk.get("recommendation", "")
        severity_bd = risk.get("severity_breakdown", {})
        category_bd = risk.get("category_breakdown", {})

        # Color for risk level
        level_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "MINIMAL": "#17a2b8",
        }
        level_color = level_colors.get(level, "#6c757d")

        # Build findings rows
        displayed_findings = self._get_displayed_findings(findings)
        findings_rows = self._build_findings_rows(displayed_findings)

        # Chart data
        sev_labels = json.dumps(list(severity_bd.keys()))
        sev_values = json.dumps(list(severity_bd.values()))
        sev_colors = json.dumps([
            self._severity_color(s) for s in severity_bd.keys()
        ])

        cat_labels = json.dumps(list(category_bd.keys()))
        cat_values = json.dumps(list(category_bd.values()))

        dep_count = sum(1 for f in findings if f.get("type") == "dependency")
        src_count = sum(1 for f in findings if f.get("type") == "source_code")
        skill_count = sum(1 for f in findings if f.get("type") == "skill")
        vuln_count = sum(1 for f in findings if f.get("type") == "vulnerability")
        unique_files = len({str(f.get("file", "")) for f in findings if f.get("file")})
        unique_cves = len({str(f.get("cve", "")) for f in findings if f.get("cve")})
        context_findings = sum(
            1 for f in findings if self._is_context_path(str(f.get("file", "")))
        )
        top_categories_summary = self._build_top_categories_summary(category_bd)

        # CVE findings
        cve_findings = [f for f in findings if f.get("cve")]
        cve_section = self._build_cve_section(cve_findings)
        threat_intel_section = (
            self._build_executive_summary_section(risk, findings, meta)
            if is_concise else
            self._build_threat_intel_section(findings)
        )

        report_label = "Concise Executive Report" if is_concise else "Full Technical Report"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>McAfee OpenClaw Security Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #161b22, #21262d); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 24px; text-align: center; }}
        .header h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 8px; }}
        .header .subtitle {{ color: #8b949e; font-size: 14px; }}
        .header .report-profile {{ color: #79c0ff; font-size: 12px; margin-top: 6px; letter-spacing: 0.4px; text-transform: uppercase; }}
        .mcafee-logo {{ color: #e63946; font-weight: bold; font-size: 16px; margin-bottom: 12px; }}

        .risk-card {{ background: linear-gradient(135deg, #161b22, #21262d); border: 2px solid {level_color}; border-radius: 12px; padding: 30px; margin-bottom: 24px; text-align: center; }}
        .risk-score {{ font-size: 72px; font-weight: bold; color: {level_color}; }}
        .risk-label {{ font-size: 24px; color: {level_color}; font-weight: 600; margin: 8px 0; }}
        .risk-recommendation {{ color: #8b949e; font-size: 16px; margin-top: 12px; }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-value {{ font-size: 36px; font-weight: bold; }}
        .stat-label {{ color: #8b949e; font-size: 13px; margin-top: 4px; }}
        .stat-critical {{ color: #f85149; }}
        .stat-high {{ color: #fd7e14; }}
        .stat-medium {{ color: #d29922; }}
        .stat-low {{ color: #3fb950; }}

        .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
        .chart-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
        .chart-card h3 {{ color: #58a6ff; margin-bottom: 16px; font-size: 16px; }}

        .findings-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .findings-section h3 {{ color: #58a6ff; margin-bottom: 16px; font-size: 18px; }}
        .triage-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
        .triage-card h3 {{ color: #58a6ff; margin-bottom: 10px; font-size: 16px; }}
        .triage-card p {{ color: #8b949e; font-size: 13px; }}
        .triage-card .triage-metrics {{ margin-top: 10px; display: flex; flex-wrap: wrap; gap: 8px; }}
        .triage-card .triage-pill {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; border-radius: 999px; padding: 4px 10px; font-size: 12px; }}
        .findings-controls {{ display: grid; grid-template-columns: 1fr auto; gap: 10px; margin-bottom: 14px; }}
        .findings-search {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; padding: 8px 10px; font-size: 13px; width: 100%; }}
        .findings-search:focus {{ outline: none; border-color: #58a6ff; }}
        .findings-filter-row {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
        .filter-btn {{ background: #0d1117; color: #8b949e; border: 1px solid #30363d; border-radius: 14px; font-size: 11px; padding: 4px 10px; cursor: pointer; text-transform: uppercase; }}
        .filter-btn:hover {{ border-color: #58a6ff; color: #c9d1d9; }}
        .filter-btn.active {{ border-color: #58a6ff; color: #58a6ff; }}
        .filter-toggle {{ display: inline-flex; gap: 6px; align-items: center; color: #8b949e; font-size: 12px; }}
        .finding-card.hidden {{ display: none; }}

        .finding-card {{ background: #0d1117; border: 1px solid #21262d; border-radius: 8px; margin-bottom: 8px; overflow: hidden; }}
        .finding-card details {{ }}
        .finding-card summary {{ padding: 12px 16px; cursor: pointer; display: flex; align-items: center; gap: 10px; font-size: 13px; list-style: none; }}
        .finding-card summary::-webkit-details-marker {{ display: none; }}
        .finding-card summary::before {{ content: '\\25B6'; font-size: 10px; color: #484f58; transition: transform 0.2s; flex-shrink: 0; }}
        .finding-card details[open] summary::before {{ transform: rotate(90deg); }}
        .finding-card summary:hover {{ background: #161b22; }}
        .finding-card .finding-summary-row {{ display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }}
        .finding-card .finding-title {{ font-weight: 600; color: #c9d1d9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .finding-card .finding-file {{ color: #484f58; font-family: monospace; font-size: 11px; margin-left: auto; white-space: nowrap; flex-shrink: 0; }}
        .finding-detail {{ padding: 0 16px 16px 36px; border-top: 1px solid #21262d; }}
        .finding-detail .detail-row {{ margin-top: 10px; }}
        .finding-detail .detail-label {{ color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }}
        .finding-detail .detail-value {{ color: #c9d1d9; font-size: 13px; }}
        .finding-detail .detail-value code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #79c0ff; }}
        .finding-detail .detail-reason {{ background: #161b22; border-left: 3px solid #58a6ff; padding: 8px 12px; margin-top: 8px; border-radius: 0 4px 4px 0; }}
        .finding-detail .detail-reason p {{ color: #8b949e; font-size: 12px; }}
        .finding-detail .cve-tag {{ display: inline-block; background: rgba(248,81,73,0.15); color: #f85149; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-top: 6px; }}
        .finding-detail .mitre-tag {{ display: inline-block; background: rgba(88,166,255,0.15); color: #58a6ff; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-top: 6px; margin-left: 4px; }}
        .finding-detail .ref-links {{ margin-top: 8px; }}
        .finding-detail .ref-links .detail-label {{ margin-bottom: 4px; }}
        .finding-detail .ref-links a {{ color: #58a6ff; font-size: 12px; text-decoration: none; display: block; padding: 2px 0; word-break: break-all; }}
        .finding-detail .ref-links a:hover {{ text-decoration: underline; }}
        .finding-detail .ref-links a::before {{ content: '\\2197\\FE0F '; font-size: 10px; }}

        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; flex-shrink: 0; }}
        .badge-critical {{ background: rgba(248,81,73,0.2); color: #f85149; }}
        .badge-high {{ background: rgba(253,126,20,0.2); color: #fd7e14; }}
        .badge-medium {{ background: rgba(210,153,34,0.2); color: #d29922; }}
        .badge-low {{ background: rgba(63,185,80,0.2); color: #3fb950; }}
        .badge-info {{ background: rgba(88,166,255,0.2); color: #58a6ff; }}

        .type-tag {{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; color: #8b949e; background: #21262d; flex-shrink: 0; }}

        .threat-intel {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .threat-intel h3 {{ color: #f85149; margin-bottom: 16px; font-size: 18px; }}
        .threat-intel .intel-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        .threat-intel .intel-card {{ background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 16px; }}
        .threat-intel .intel-card h4 {{ color: #58a6ff; font-size: 14px; margin-bottom: 8px; }}
        .threat-intel .intel-card p {{ color: #8b949e; font-size: 13px; }}
        .threat-intel .intel-card ul {{ color: #8b949e; font-size: 12px; margin: 8px 0 0 16px; }}
        .threat-intel .intel-card ul li {{ margin-bottom: 4px; }}
        .threat-intel .intel-card .impact-list {{ list-style: none; margin: 8px 0 0 0; padding: 0; }}
        .threat-intel .intel-card .impact-list li {{ padding: 4px 0; border-bottom: 1px solid #161b22; font-size: 12px; color: #c9d1d9; }}
        .threat-intel .intel-card .impact-list li:last-child {{ border-bottom: none; }}
        .threat-intel .intel-card .impact-list .il-sev {{ font-weight: 600; margin-right: 4px; }}

        .intel-card details {{ margin-top: 8px; }}
        .intel-card details summary {{ cursor: pointer; color: #58a6ff; font-size: 12px; padding: 4px 0; }}
        .intel-card details summary:hover {{ text-decoration: underline; }}
        .intel-card details .expanded-list {{ margin-top: 8px; max-height: 300px; overflow-y: auto; }}
        .intel-card details .expanded-list::-webkit-scrollbar {{ width: 6px; }}
        .intel-card details .expanded-list::-webkit-scrollbar-track {{ background: #0d1117; }}
        .intel-card details .expanded-list::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 3px; }}

        .cve-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .cve-section h3 {{ color: #f85149; margin-bottom: 16px; font-size: 18px; }}
        .cve-card {{ background: #0d1117; border-left: 4px solid #f85149; border-radius: 0 8px 8px 0; padding: 16px; margin-bottom: 12px; }}
        .cve-card .cve-id {{ color: #f85149; font-weight: bold; font-size: 16px; }}
        .cve-card .cve-cvss {{ display: inline-block; background: rgba(248,81,73,0.2); color: #f85149; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }}
        .cve-card .cve-desc {{ color: #c9d1d9; font-size: 13px; margin-top: 8px; }}
        .cve-card .cve-file {{ color: #8b949e; font-size: 12px; font-family: monospace; margin-top: 6px; }}

        .ioc-section {{ margin-top: 16px; }}
        .ioc-section h4 {{ color: #58a6ff; font-size: 14px; margin-bottom: 8px; }}
        .ioc-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12px; font-family: monospace; }}
        .ioc-cell {{ background: #0d1117; padding: 8px; border-radius: 4px; }}
        .ioc-cell strong {{ color: #f85149; }}

        .footer {{ text-align: center; color: #484f58; font-size: 12px; padding: 20px; border-top: 1px solid #21262d; margin-top: 24px; }}

        @media (max-width: 768px) {{
            .charts-grid {{ grid-template-columns: 1fr; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .threat-intel .intel-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="mcafee-logo">McAFEE SECURITY</div>
            <h1>OpenClaw Pre-Install Security Audit</h1>
            <div class="subtitle">
                Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')} |
                Repository: {html.escape(meta.get('repo_path', 'unknown'))} |
                Files Scanned: {meta.get('files_scanned', 'N/A')} |
                Skills Analyzed: {meta.get('skills_scanned', 'N/A')}
            </div>
            <div class="report-profile">{report_label}</div>
        </div>

        <div class="risk-card">
            <div class="risk-score">{score}</div>
            <div class="risk-label">RISK LEVEL: {level}</div>
            <div class="risk-recommendation">{html.escape(recommendation)}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value stat-critical">{severity_bd.get('critical', 0)}</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-high">{severity_bd.get('high', 0)}</div>
                <div class="stat-label">High Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-medium">{severity_bd.get('medium', 0)}</div>
                <div class="stat-label">Medium Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-low">{severity_bd.get('low', 0) + severity_bd.get('info', 0)}</div>
                <div class="stat-label">Low / Info</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color:#58a6ff">{dep_count}</div>
                <div class="stat-label">Dependency Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#bc8cff">{src_count}</div>
                <div class="stat-label">Source Code Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#f778ba">{skill_count}</div>
                <div class="stat-label">Skill Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#ff7b72">{vuln_count}</div>
                <div class="stat-label">Vulnerability / CVE Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#79c0ff">{len(findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <div class="triage-card">
            <h3>Triage Overview</h3>
            <p>
                Focus on <strong style="color:#c9d1d9">critical/high</strong> findings in executable code paths first.
                Documentation/test references are useful context but often lower-confidence for active compromise.
            </p>
            <div class="triage-metrics">
                <span class="triage-pill">Unique files with findings: {unique_files}</span>
                <span class="triage-pill">Unique CVEs referenced: {unique_cves}</span>
                <span class="triage-pill">Context/docs/test findings: {context_findings}</span>
                <span class="triage-pill">Top categories: {top_categories_summary}</span>
            </div>
        </div>

        {threat_intel_section}

        {cve_section}

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Findings by Category</h3>
                <canvas id="categoryChart"></canvas>
            </div>
        </div>

        <div class="findings-section">
            <h3>
                {'Top Findings' if is_concise else 'All Findings'}
                (<span id="visibleFindingCount">{len(displayed_findings)}</span> / {len(displayed_findings)})
            </h3>
            <div class="findings-controls">
                <input id="findingSearch" class="findings-search" type="text" placeholder="Search title, file, category..." />
                <div class="findings-filter-row">
                    <button class="filter-btn active" data-severity="all" type="button">All</button>
                    <button class="filter-btn" data-severity="critical" type="button">Critical</button>
                    <button class="filter-btn" data-severity="high" type="button">High</button>
                    <button class="filter-btn" data-severity="medium" type="button">Medium</button>
                    <button class="filter-btn" data-severity="low" type="button">Low</button>
                    <button class="filter-btn" data-severity="info" type="button">Info</button>
                    <label class="filter-toggle">
                        <input id="hideContextFindings" type="checkbox" />
                        Hide docs/tests
                    </label>
                </div>
            </div>
            {findings_rows}
        </div>

        <div class="footer">
            McAfee OpenClaw Pre-Install Security Auditor v1.0.0 |
            Proof of Concept - For demonstration purposes |
            &copy; {datetime.now().year} McAfee Security
        </div>
    </div>

    <script>
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: {sev_labels},
                datasets: [{{
                    data: {sev_values},
                    backgroundColor: {sev_colors},
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#c9d1d9', font: {{ size: 12 }} }}
                    }}
                }}
            }}
        }});

        const catCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(catCtx, {{
            type: 'bar',
            data: {{
                labels: {cat_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {cat_values},
                    backgroundColor: '#58a6ff',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                indexAxis: 'y',
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    x: {{
                        ticks: {{ color: '#8b949e' }},
                        grid: {{ color: '#21262d' }}
                    }},
                    y: {{
                        ticks: {{ color: '#c9d1d9', font: {{ size: 11 }} }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});

        const searchInput = document.getElementById('findingSearch');
        const hideContext = document.getElementById('hideContextFindings');
        const findingCards = Array.from(document.querySelectorAll('.finding-card'));
        const severityButtons = Array.from(document.querySelectorAll('.filter-btn'));
        const visibleCount = document.getElementById('visibleFindingCount');
        let activeSeverity = 'all';

        function applyFindingFilters() {{
            const query = (searchInput?.value || '').toLowerCase().trim();
            const hideContextEnabled = !!hideContext?.checked;
            let visible = 0;
            findingCards.forEach((card) => {{
                const sev = card.dataset.severity || '';
                const text = card.dataset.search || '';
                const isContext = card.dataset.context === '1';
                const severityMatches = activeSeverity === 'all' || sev === activeSeverity;
                const queryMatches = !query || text.includes(query);
                const contextMatches = !hideContextEnabled || !isContext;
                const show = severityMatches && queryMatches && contextMatches;
                card.classList.toggle('hidden', !show);
                if (show) visible += 1;
            }});
            if (visibleCount) {{
                visibleCount.textContent = String(visible);
            }}
        }}

        severityButtons.forEach((btn) => {{
            btn.addEventListener('click', () => {{
                activeSeverity = btn.dataset.severity || 'all';
                severityButtons.forEach((b) => b.classList.remove('active'));
                btn.classList.add('active');
                applyFindingFilters();
            }});
        }});
        searchInput?.addEventListener('input', applyFindingFilters);
        hideContext?.addEventListener('change', applyFindingFilters);
    </script>
</body>
</html>"""

    def _sort_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity, then file/location, then title."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(str(f.get("severity", "info")).lower(), 5),
                str(f.get("file", "")),
                int(f.get("line", 0) or 0),
                str(f.get("title", "")),
            ),
        )

    def _is_context_path(self, path: str) -> bool:
        """
        Return True for docs/tests/examples paths where findings are often
        contextual references rather than executable attack paths.
        """
        p = (path or "").lower()
        context_tokens = [
            "/docs/", "\\docs\\", "readme", "changelog",
            "/test/", "\\test\\", "/tests/", "\\tests\\",
            "example", "sample", ".md", ".mdx",
        ]
        return any(token in p for token in context_tokens)

    def _build_top_categories_summary(self, category_breakdown: Dict[str, int], limit: int = 4) -> str:
        """Build a short comma-separated summary of top finding categories."""
        if not category_breakdown:
            return "none"
        sorted_categories = sorted(
            category_breakdown.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[:limit]
        return ", ".join(f"{k} ({v})" for k, v in sorted_categories)

    def _get_displayed_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Select findings shown in the report body.
        Full profile: all findings.
        Concise profile: all critical/high, then top medium/low/info up to 40 total.
        """
        sorted_findings = self._sort_findings(findings)
        if self.report_profile != "concise":
            return sorted_findings

        high_priority = [
            f for f in sorted_findings
            if str(f.get("severity", "info")).lower() in {"critical", "high"}
        ]
        remaining = [f for f in sorted_findings if f not in high_priority]
        target_limit = 40
        if len(high_priority) >= target_limit:
            return high_priority[:target_limit]
        return high_priority + remaining[: target_limit - len(high_priority)]

    def _build_executive_summary_section(
        self,
        risk: Dict[str, Any],
        findings: List[Dict[str, Any]],
        meta: Dict[str, Any],
    ) -> str:
        """Build a concise executive summary section for sharing."""
        severity = risk.get("severity_breakdown", {})
        top_issues = self._sort_findings(findings)[:5]
        top_lines = []
        for issue in top_issues:
            sev = str(issue.get("severity", "info")).upper()
            title = html.escape(str(issue.get("title", "Unknown")))
            file_path = html.escape(str(issue.get("file", "N/A")))
            top_lines.append(
                f"<li><strong>[{sev}]</strong> {title}<br>"
                f"<span style='color:#8b949e;font-family:monospace;font-size:11px'>{file_path}</span></li>"
            )
        top_issues_html = "".join(top_lines) if top_lines else "<li>No findings.</li>"
        return f"""
        <div class="threat-intel">
            <h3>Executive Summary</h3>
            <p style="color:#8b949e;margin-bottom:12px">
                This concise report highlights the most actionable risks for rapid stakeholder review.
            </p>
            <div class="intel-grid">
                <div class="intel-card">
                    <h4 style="color:#58a6ff">Scan Snapshot</h4>
                    <ul style="margin:8px 0 0 16px;color:#c9d1d9;font-size:12px">
                        <li>Risk score: {risk.get('risk_score', 0)} / 100 ({html.escape(str(risk.get('risk_level', 'UNKNOWN')))})</li>
                        <li>Total findings: {len(findings)}</li>
                        <li>Critical: {severity.get('critical', 0)} | High: {severity.get('high', 0)} | Medium: {severity.get('medium', 0)}</li>
                        <li>Files scanned: {meta.get('files_scanned', 'N/A')} | Skills analyzed: {meta.get('skills_scanned', 'N/A')}</li>
                    </ul>
                </div>
                <div class="intel-card">
                    <h4 style="color:#58a6ff">Recommendation</h4>
                    <p>{html.escape(str(risk.get('recommendation', 'Review findings before installation.')))}</p>
                </div>
                <div class="intel-card">
                    <h4 style="color:#58a6ff">Top 5 Findings</h4>
                    <ul style="margin:8px 0 0 16px;color:#c9d1d9;font-size:12px">
                        {top_issues_html}
                    </ul>
                </div>
                <div class="intel-card">
                    <h4 style="color:#58a6ff">Audience Guidance</h4>
                    <ul style="margin:8px 0 0 16px;color:#c9d1d9;font-size:12px">
                        <li>Security reviewers: validate critical/high findings first.</li>
                        <li>Engineering: prioritize files with repeated high-severity hits.</li>
                        <li>Leadership: use this summary for go/no-go decisions.</li>
                    </ul>
                </div>
            </div>
        </div>"""

    def _build_findings_rows(self, findings: List[Dict]) -> str:
        """Build collapsible finding cards. Each finding is collapsed by default
        with a summary line, and expands to show full details on click."""
        sorted_findings = self._sort_findings(findings)

        cards = []
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "info").lower()
            badge_class = f"badge-{sev}"
            ftype = f.get("type", "")
            title = html.escape(f.get("title", ""))
            file_path = html.escape(f.get("file", ""))
            desc = html.escape(f.get("description", ""))
            reason = html.escape(f.get("reason", ""))
            line = f.get("line", "")
            location = f"{file_path}:{line}" if line else file_path
            cve = f.get("cve", "")
            cvss = f.get("cvss", "")
            category = html.escape(f.get("category", ""))
            context_flag = "1" if self._is_context_path(str(f.get("file", ""))) else "0"
            search_blob = " ".join([
                str(f.get("title", "")),
                str(f.get("file", "")),
                str(f.get("category", "")),
                str(f.get("type", "")),
                str(f.get("description", "")),
            ]).lower()
            search_attr = html.escape(search_blob, quote=True)

            # Build detail section
            detail_parts = []

            # Description
            detail_parts.append(f"""
                <div class="detail-row">
                    <div class="detail-label">Description</div>
                    <div class="detail-value">{desc}</div>
                </div>""")

            # File location
            detail_parts.append(f"""
                <div class="detail-row">
                    <div class="detail-label">Location</div>
                    <div class="detail-value"><code>{location}</code></div>
                </div>""")

            # Category
            if category:
                detail_parts.append(f"""
                <div class="detail-row">
                    <div class="detail-label">Category</div>
                    <div class="detail-value">{category}</div>
                </div>""")

            # Reason / Supporting Evidence
            if reason:
                detail_parts.append(f"""
                <div class="detail-reason">
                    <div class="detail-label">Why This Matters</div>
                    <p>{reason}</p>
                </div>""")

            # CVE & CVSS tags
            tags_html = ""
            if cve:
                tags_html += f'<span class="cve-tag">{html.escape(cve)}</span>'
            if cvss:
                tags_html += f'<span class="cve-tag">CVSS {html.escape(str(cvss))}</span>'
            if tags_html:
                detail_parts.append(f"""
                <div class="detail-row" style="margin-top:8px">
                    {tags_html}
                </div>""")

            # Reference links
            refs = list(dict.fromkeys(f.get("references", [])))
            if refs:
                refs = refs[:6]
                ref_links = "".join(
                    f'<a href="{html.escape(url)}" target="_blank" rel="noopener">{html.escape(url)}</a>'
                    for url in refs
                )
                detail_parts.append(f"""
                <div class="ref-links">
                    <div class="detail-label">References</div>
                    {ref_links}
                </div>""")

            detail_content = "".join(detail_parts)

            cards.append(f"""
            <div class="finding-card" data-severity="{html.escape(sev, quote=True)}" data-context="{context_flag}" data-search="{search_attr}">
                <details>
                    <summary>
                        <div class="finding-summary-row">
                            <span class="badge {badge_class}">{sev}</span>
                            <span class="type-tag">{html.escape(ftype)}</span>
                            <span class="finding-title">#{i} {title}</span>
                            <span class="finding-file">{location}</span>
                        </div>
                    </summary>
                    <div class="finding-detail">
                        {detail_content}
                    </div>
                </details>
            </div>""")

        if not cards:
            return '<div style="text-align:center;color:#3fb950;padding:20px">No findings - looking clean!</div>'

        return "\n".join(cards)

    def _build_threat_intel_section(self, findings: List[Dict]) -> str:
        """Build threat intelligence overview section with enriched details
        and collapsible lists for related findings from the scan."""
        vuln_findings = [f for f in findings if f.get("type") == "vulnerability"]
        src_findings = [f for f in findings if f.get("type") == "source_code"]
        auth_issues = [f for f in vuln_findings if f.get("category") in (
            "auth_bypass", "dangerous_config", "privilege_escalation")]
        sandbox_issues = [f for f in vuln_findings if f.get("category") in (
            "approval_bypass", "sandbox_escape")]
        cred_issues = [f for f in vuln_findings if f.get("category") in (
            "credential_storage", "information_disclosure")]
        marketplace_issues = [f for f in vuln_findings if f.get("category") == "supply_chain"]

        # Gather CVE-2026-25253 related findings from scan
        cve_related = [f for f in findings if f.get("cve") == "CVE-2026-25253"]
        cve_related_html = self._build_related_findings_list(cve_related)

        # Gather ClawHavoc campaign related findings (source code patterns that
        # map to the campaign's TTPs: base64, gatekeeper, crypto wallet, credentials)
        campaign_categories = {
            "crypto_wallet", "gatekeeper_bypass", "dangerous_command",
            "credential_harvesting", "obfuscation", "paste_service",
        }
        campaign_findings = [
            f for f in src_findings
            if f.get("category") in campaign_categories
        ]
        # Also include vuln findings about exec/approval bypass (the attack chain)
        campaign_findings += [
            f for f in vuln_findings
            if f.get("category") in ("approval_bypass", "sandbox_escape",
                                      "agent_manipulation")
        ]
        campaign_html = self._build_related_findings_list(campaign_findings)
        campaign_count = len(campaign_findings)

        # Gather exposed control UI related findings
        control_findings = [
            f for f in vuln_findings
            if f.get("category") in ("auth_bypass", "dangerous_config")
        ]
        control_html = self._build_related_findings_list(control_findings)
        cve_status = (
            f"{len(cve_related)} direct CVE-2026-25253 indicator(s) found in this scan."
            if cve_related else
            "No direct CVE-2026-25253 indicators found in scanned files."
        )
        campaign_status = (
            f"{campaign_count} campaign-aligned indicator(s) found."
            if campaign_count else
            "No campaign-aligned indicators found."
        )

        return f"""
        <div class="threat-intel">
            <h3>Threat Intelligence Summary</h3>
            <p style="color:#8b949e;margin-bottom:16px">
                Threat model context is shown alongside scan evidence from this repository.
                Use the related-findings lists in each card to validate whether a specific threat
                is directly supported by findings in this scan.
            </p>
            <p style="color:#8b949e;margin-bottom:12px;font-size:12px">
                {html.escape(cve_status)} {html.escape(campaign_status)}
            </p>
            <div class="intel-grid">
                <div class="intel-card">
                    <h4 style="color:#f85149">CVE-2026-25253: 1-Click RCE (CVSS 8.8)</h4>
                    <p>The <code style="background:#161b22;padding:2px 4px;border-radius:3px;color:#f85149">gatewayUrl</code>
                    parameter is accepted from URL query strings without an explicit user confirmation dialog.
                    An attacker sends a victim a crafted link like
                    <code style="background:#161b22;padding:2px 4px;border-radius:3px;font-size:11px">?gatewayUrl=attacker.com/ws</code>
                    which silently redirects the WebSocket connection to an attacker-controlled server,
                    exfiltrating the authentication token.</p>

                    <div style="margin-top:10px;background:#161b22;border-radius:6px;padding:10px;font-size:12px">
                        <strong style="color:#f85149">Impact on unpatched users (before v2026.1.29):</strong>
                        <ul style="margin:6px 0 0 16px;color:#c9d1d9">
                            <li><strong>Token theft</strong> - Auth token sent to attacker's WebSocket server</li>
                            <li><strong>Sandbox escape</strong> - Attacker calls <code style="background:#0d1117;padding:1px 4px;border-radius:3px">config.patch</code> to switch execution from sandbox to host</li>
                            <li><strong>Approval bypass</strong> - Attacker calls <code style="background:#0d1117;padding:1px 4px;border-radius:3px">exec.approvals.set</code> to disable all command confirmations</li>
                            <li><strong>Full RCE</strong> - Arbitrary commands execute on victim's machine without any prompt</li>
                            <li><strong>Credential theft</strong> - All API keys, tokens, and secrets in ~/.clawdbot/.env are accessible</li>
                        </ul>
                        <p style="color:#f85149;margin-top:8px;font-weight:600">
                            Users running OpenClaw versions prior to v2026.1.29 are fully exposed to this
                            attack chain. A single click on a malicious link is sufficient for complete system compromise.
                        </p>
                    </div>

                    <details style="margin-top:10px">
                        <summary>View {len(cve_related)} related findings from this scan</summary>
                        <div class="expanded-list">
                            {cve_related_html}
                        </div>
                    </details>
                </div>

                <div class="intel-card">
                    <h4 style="color:#fd7e14">ClawHavoc Campaign - Attack Patterns Detected</h4>
                    <p>Our scan detected <strong style="color:#c9d1d9">{campaign_count} findings</strong>
                    matching known ClawHavoc campaign techniques. The campaign uses ClickFix social
                    engineering popups to trick users into running malicious skills that:</p>

                    <ul style="margin:8px 0 0 16px;color:#c9d1d9;font-size:12px">
                        <li>Encode payloads in Base64 to evade static analysis</li>
                        <li>Download dropper files to <code style="background:#161b22;padding:1px 4px;border-radius:3px">$TMPDIR</code> via silent curl</li>
                        <li>Clear macOS Gatekeeper quarantine flags (<code style="background:#161b22;padding:1px 4px;border-radius:3px">xattr -cr</code>) to bypass security</li>
                        <li>Exfiltrate crypto wallet keys (Solana, Phantom, MetaMask)</li>
                        <li>Harvest API keys from <code style="background:#161b22;padding:1px 4px;border-radius:3px">~/.clawdbot/.env</code></li>
                    </ul>

                    <details>
                        <summary>View all {campaign_count} matching findings from this scan</summary>
                        <div class="expanded-list">
                            {campaign_html}
                        </div>
                    </details>
                </div>

                <div class="intel-card">
                    <h4 style="color:#fd7e14">Exposed Control Servers - Authentication Bypass</h4>
                    <p>The OpenClaw gateway has a <strong style="color:#c9d1d9">localhost auto-approve</strong>
                    mechanism: connections from 127.0.0.1 are automatically authenticated without
                    device pairing. This creates a critical vulnerability when deployed behind a
                    reverse proxy:</p>

                    <div style="margin-top:8px;background:#161b22;border-radius:6px;padding:10px;font-size:12px">
                        <strong style="color:#fd7e14">Attack scenario:</strong>
                        <ol style="margin:6px 0 0 16px;color:#c9d1d9">
                            <li>Admin deploys OpenClaw behind nginx/Caddy reverse proxy</li>
                            <li>Proxy forwards requests - all connections arrive from 127.0.0.1</li>
                            <li><code style="background:#0d1117;padding:1px 4px;border-radius:3px">trustedProxies</code> defaults to empty, so X-Forwarded-For is ignored</li>
                            <li>Gateway auto-approves ALL connections as "localhost" / trusted</li>
                            <li>Any internet user gets full authenticated access without credentials</li>
                        </ol>
                        <p style="color:#fd7e14;margin-top:8px">
                            Hundreds of such exposed instances have been documented on Shodan,
                            giving unauthenticated attackers full command execution and credential access.
                        </p>
                    </div>

                    <details>
                        <summary>View {len(control_findings)} related findings from this scan</summary>
                        <div class="expanded-list">
                            {control_html}
                        </div>
                    </details>
                </div>

                <div class="intel-card">
                    <h4 style="color:#d29922">ClawHub Marketplace Trust Manipulation</h4>
                    <p>~20% of skills on the ClawHub marketplace have been identified as malicious.
                    Threat actors manipulate download counts and ratings to make trojanized skills
                    appear popular and trustworthy. Users install these skills without reviewing
                    the underlying source code.</p>

                    <div style="margin-top:8px;background:#161b22;border-radius:6px;padding:10px;font-size:12px">
                        <strong style="color:#d29922">Known malicious patterns on ClawHub:</strong>
                        <ul style="margin:6px 0 0 16px;color:#c9d1d9">
                            <li>Skills with random alphanumeric suffixes (e.g., <code style="background:#0d1117;padding:1px 4px;border-radius:3px">polymarket-7ceau</code>, <code style="background:#0d1117;padding:1px 4px;border-radius:3px">phantom-0jcvy</code>)</li>
                            <li>Mass-published by single authors (~199 skills from one account)</li>
                            <li>Impersonate popular crypto tools (Phantom, Solana, Jupiter)</li>
                            <li>Fake download counts to game marketplace ranking</li>
                        </ul>
                        <p style="margin-top:8px;color:#8b949e">
                            Browse <a href="https://clawhub.ai/explore" target="_blank" style="color:#58a6ff">ClawHub Explore</a>
                            and search for skills with short random suffixes to see examples of this pattern.
                        </p>
                    </div>
                </div>

                <div class="intel-card">
                    <h4>Architecture Risk Assessment</h4>
                    <p>
                        Auth bypass issues found: <strong style="color:#f85149">{len(auth_issues)}</strong><br>
                        Sandbox escape vectors: <strong style="color:#f85149">{len(sandbox_issues)}</strong><br>
                        Credential exposure: <strong style="color:#fd7e14">{len(cred_issues)}</strong><br>
                        Supply chain risks: <strong style="color:#d29922">{len(marketplace_issues)}</strong>
                    </p>
                    <p style="color:#f85149;margin-top:8px;font-weight:600">
                        The OpenClaw agent runs with the user's full system privileges by design.
                        Any compromise of the auth token, gateway, or skill system gives the
                        attacker complete control over the host machine.
                    </p>
                </div>

                <div class="intel-card">
                    <h4>Social Engineering Vectors</h4>
                    <p>Documented attack vectors used against OpenClaw users:</p>
                    <ul style="margin:8px 0 0 16px;color:#c9d1d9;font-size:12px">
                        <li><strong>ClickFix popups</strong> - Fake error dialogs trick users into running malicious commands</li>
                        <li><strong>Crafted gateway URLs</strong> - Shared via chat/email to steal tokens (CVE-2026-25253)</li>
                        <li><strong>Trojanized skills</strong> - Look-alike skills on ClawHub with hidden payloads</li>
                        <li><strong>AMOS Stealer delivery</strong> - macOS Gatekeeper bypass via xattr clearing</li>
                    </ul>
                </div>
            </div>

            <div class="ioc-section">
                <h4>Indicators of Compromise (IOCs)</h4>
                <div class="ioc-grid">
                    <div class="ioc-cell">
                        <strong>Malicious IPs:</strong><br>
                        91.92.242.30 (C2 server)<br>
                        54.91.154.110:13338 (reverse shell)
                    </div>
                    <div class="ioc-cell">
                        <strong>Malicious Domains:</strong><br>
                        socifiapp[.]com/api/reports/upload<br>
                        webhook[.]site/358866c4-...
                    </div>
                    <div class="ioc-cell">
                        <strong>Credential Targets:</strong><br>
                        ~/.clawdbot/.env (API keys)<br>
                        SOLANA_KEYPAIR_PATH, POLYMARKET_API_KEY
                    </div>
                    <div class="ioc-cell">
                        <strong>Detection Rules:</strong><br>
                        PHASR.Base64.Decode, PHASR.Curl.Silent<br>
                        EDR.GatekeeperQuarantineBypass
                    </div>
                </div>
            </div>
        </div>"""

    def _build_related_findings_list(self, findings: List[Dict]) -> str:
        """Build a compact HTML list of findings for embedding in collapsible sections."""
        if not findings:
            return '<p style="color:#484f58;font-size:12px;padding:4px 0">No related findings detected.</p>'

        findings = self._sort_findings(findings)
        items = []
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_colors = {
                "critical": "#f85149", "high": "#fd7e14",
                "medium": "#d29922", "low": "#3fb950", "info": "#58a6ff"
            }
            color = sev_colors.get(sev, "#8b949e")
            title = html.escape(f.get("title", ""))
            file_path = html.escape(f.get("file", ""))
            line = f.get("line", "")
            loc = f"{file_path}:{line}" if line else file_path

            items.append(
                f'<li style="padding:6px 0;border-bottom:1px solid #161b22;font-size:12px">'
                f'<span style="color:{color};font-weight:600">[{sev.upper()}]</span> '
                f'{title}'
                f'<br><span style="color:#484f58;font-family:monospace;font-size:11px">{loc}</span>'
                f'</li>'
            )

        return f'<ul style="list-style:none;margin:0;padding:0">{"".join(items)}</ul>'

    def _build_cve_section(self, cve_findings: List[Dict]) -> str:
        """Build CVE details section."""
        if not cve_findings:
            return ""

        cards = []
        seen_cves = set()
        for f in self._sort_findings(cve_findings):
            cve_id = f.get("cve", "")
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            cvss = f.get("cvss", "")
            cvss_html = f'<span class="cve-cvss">CVSS {cvss}</span>' if cvss else ""
            cards.append(f"""
                <div class="cve-card">
                    <span class="cve-id">{html.escape(cve_id)}</span>{cvss_html}
                    <div class="cve-desc">{html.escape(f.get('description', ''))}</div>
                    <div class="cve-file">{html.escape(f.get('file', ''))}</div>
                </div>""")

        return f"""
        <div class="cve-section">
            <h3>CVE Details ({len(seen_cves)} unique CVEs detected)</h3>
            {"".join(cards)}
        </div>"""

    def _severity_color(self, severity: str) -> str:
        """Get color for a severity level."""
        colors = {
            "critical": "#f85149",
            "high": "#fd7e14",
            "medium": "#d29922",
            "low": "#3fb950",
            "info": "#58a6ff",
        }
        return colors.get(severity.lower(), "#6c757d")

    def _build_text(self) -> str:
        """Build plain text report."""
        risk = self.results.get("risk_summary", {})
        findings = self.results.get("findings", [])
        meta = self.results.get("scan_metadata", {})
        is_concise = self.report_profile == "concise"
        displayed_findings = self._get_displayed_findings(findings)
        category_breakdown = risk.get("category_breakdown", {})
        context_findings = sum(
            1 for f in findings if self._is_context_path(str(f.get("file", "")))
        )
        high_priority = [
            f for f in findings
            if str(f.get("severity", "info")).lower() in {"critical", "high"}
        ]
        top_files = Counter(
            str(f.get("file", "N/A"))
            for f in high_priority
            if f.get("file")
        ).most_common(8)
        top_categories = sorted(
            category_breakdown.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[:8]

        lines = [
            "=" * 70,
            "  McAfee OpenClaw Pre-Install Security Audit Report",
            "=" * 70,
            "",
            f"  Report Profile:  {'CONCISE' if is_concise else 'FULL'}",
            f"  Generated:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Repository:      {meta.get('repo_path', 'unknown')}",
            f"  Files Scanned:   {meta.get('files_scanned', 'N/A')}",
            f"  Skills Analyzed: {meta.get('skills_scanned', 'N/A')}",
            f"  Duration:        {meta.get('scan_duration_seconds', 'N/A')}s",
            "",
            "-" * 70,
            f"  RISK SCORE:      {risk.get('risk_score', 0)} / 100",
            f"  RISK LEVEL:      {risk.get('risk_level', 'UNKNOWN')}",
            f"  RECOMMENDATION:  {risk.get('recommendation', '')}",
            "-" * 70,
            "",
            f"  Total Findings:  {len(findings)}",
            f"  Critical:        {risk.get('severity_breakdown', {}).get('critical', 0)}",
            f"  High:            {risk.get('severity_breakdown', {}).get('high', 0)}",
            f"  Medium:          {risk.get('severity_breakdown', {}).get('medium', 0)}",
            f"  Low:             {risk.get('severity_breakdown', {}).get('low', 0)}",
            f"  Info:            {risk.get('severity_breakdown', {}).get('info', 0)}",
            f"  Context Findings:{context_findings}",
            "",
            "-" * 70,
            "  TOP CATEGORIES",
            "-" * 70,
        ]

        if top_categories:
            for name, count in top_categories:
                lines.append(f"  - {name}: {count}")
        else:
            lines.append("  - none")

        lines.extend([
            "",
            "-" * 70,
            "  MOST AFFECTED FILES (CRITICAL/HIGH)",
            "-" * 70,
        ])

        if top_files:
            for path, count in top_files:
                lines.append(f"  - {path}: {count}")
        else:
            lines.append("  - none")

        lines.extend([
            "",
            "=" * 70,
            "  DETAILED FINDINGS" if not is_concise else "  TOP FINDINGS (CONCISE)",
            "=" * 70,
            "",
        ])

        sorted_findings = self._sort_findings(displayed_findings)

        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"  [{f.get('severity', 'info').upper()}] #{i}: {f.get('title', 'Unknown')}")
            lines.append(f"    File: {f.get('file', 'N/A')}")
            if f.get("line"):
                lines.append(f"    Line: {f['line']}")
            lines.append(f"    {f.get('description', '')}")
            if f.get("reason"):
                lines.append(f"    Reason: {f['reason']}")
            if f.get("cve"):
                lines.append(f"    CVE: {f['cve']}")
            refs = list(dict.fromkeys(f.get("references", [])))
            if refs:
                lines.append(f"    References:")
                for ref_url in refs[:6]:
                    lines.append(f"      - {ref_url}")
            lines.append("")

        if is_concise and len(displayed_findings) < len(findings):
            lines.extend([
                "-" * 70,
                f"  NOTE: Showing {len(displayed_findings)} of {len(findings)} findings in concise mode.",
                "  Use full profile for complete technical detail.",
                "-" * 70,
                "",
            ])

        lines.extend([
            "=" * 70,
            "  McAfee OpenClaw Pre-Install Security Auditor v1.0.0",
            "=" * 70,
        ])

        return "\n".join(lines)
