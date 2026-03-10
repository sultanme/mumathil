from __future__ import annotations


class ReportAgent:
    def generate(self, website: str, evaluation: dict) -> dict:
        failed = [r for r in evaluation["rule_results"] if not r["passed"]]
        issues = [f"{r['rule_id']}: {r['description']}" for r in failed]
        recommendations = [
            "Publish a clear privacy policy in Arabic and English.",
            "Add consent controls before collecting personal data.",
            "Disclose third-party sharing and retention timelines.",
        ]

        return {
            "website": website,
            "compliance_score": evaluation["compliance_score"],
            "risk_level": evaluation["risk_level"],
            "issues": issues,
            "recommendations": recommendations,
            "passed_rules": evaluation["passed_rules"],
            "failed_rules": evaluation["failed_rules"],
        }
