"""
Risk Scorer - Calculates overall risk score and generates recommendations.
Uses weighted severity scoring on a 0-100 scale.
"""

from typing import List, Dict, Any
from collections import Counter


# Severity weights
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}

# Risk level thresholds
RISK_LEVELS = [
    (70, "CRITICAL", "DO NOT INSTALL - Significant security threats detected"),
    (50, "HIGH", "NOT RECOMMENDED - Multiple security issues found"),
    (30, "MEDIUM", "REVIEW CAREFULLY - Some security concerns detected"),
    (10, "LOW", "GENERALLY SAFE - Minor issues detected"),
    (0, "MINIMAL", "No significant security concerns detected"),
]


class RiskScorer:
    """Calculates risk scores and generates recommendations."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.score = 0
        self.level = "MINIMAL"
        self.recommendation = ""

    def calculate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate the overall risk score from all findings."""
        self.findings = findings

        # Calculate raw score
        raw_score = 0
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            weight = SEVERITY_WEIGHTS.get(severity, 0)
            raw_score += weight

        # Cap at 100
        self.score = min(raw_score, 100)

        # Determine risk level
        for threshold, level, recommendation in RISK_LEVELS:
            if self.score >= threshold:
                self.level = level
                self.recommendation = recommendation
                break

        return self.get_summary()

    def get_summary(self) -> Dict[str, Any]:
        """Get the risk assessment summary."""
        severity_counts = Counter(
            f.get("severity", "info").lower() for f in self.findings
        )
        category_counts = Counter(
            f.get("category", f.get("type", "unknown")) for f in self.findings
        )
        type_counts = Counter(
            f.get("type", "unknown") for f in self.findings
        )

        return {
            "risk_score": self.score,
            "risk_level": self.level,
            "recommendation": self.recommendation,
            "total_findings": len(self.findings),
            "severity_breakdown": dict(severity_counts),
            "category_breakdown": dict(category_counts),
            "type_breakdown": dict(type_counts),
            "top_issues": self._get_top_issues(),
        }

    def _get_top_issues(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most severe issues."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5),
        )
        return sorted_findings[:limit]
