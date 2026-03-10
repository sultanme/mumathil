from __future__ import annotations

import json
from pathlib import Path


class RuleEngineAgent:
    def __init__(self, rules_path: str | Path):
        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules = json.load(f)

    def evaluate(self, analysis_output: dict) -> dict:
        findings = analysis_output["findings"]
        rule_results = []
        for rule in self.rules:
            rule_id = rule["id"]
            mapping_key = rule["mapping_key"]
            passed = bool(findings.get(mapping_key, False))
            rule_results.append(
                {
                    "rule_id": rule_id,
                    "description": rule["description"],
                    "passed": passed,
                    "details": "Compliant" if passed else "Gap detected",
                }
            )

        passed_rules = sum(1 for r in rule_results if r["passed"])
        total_rules = len(rule_results)
        score = round((passed_rules / total_rules) * 100, 2) if total_rules else 0.0

        if score >= 80:
            risk = "low"
        elif score >= 50:
            risk = "medium"
        else:
            risk = "high"

        return {
            "rule_results": rule_results,
            "passed_rules": passed_rules,
            "failed_rules": total_rules - passed_rules,
            "compliance_score": score,
            "risk_level": risk,
        }
