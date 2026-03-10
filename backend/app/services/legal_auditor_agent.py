from __future__ import annotations


class LegalAuditorAgent:
    def generate_audit(self, website: str, findings: dict, evaluation: dict, regulatory_context: list[str]) -> str:
        score = evaluation["compliance_score"]
        risk = evaluation["risk_level"]
        deficits = [k for k, v in findings.items() if not v]
        deficits_text = ", ".join(deficits) if deficits else "no major control deficiencies"
        context_excerpt = " | ".join(regulatory_context[:2]) if regulatory_context else "No uploaded regulatory context provided."

        return (
            f"Legal Compliance Audit - {website}\n\n"
            f"Based on automated analysis of crawled website content, the organization demonstrates {('strong' if score >= 80 else 'partial')} "
            f"compliance with PDPL/SDAIA-aligned controls. The current compliance score is {score} with {risk} risk exposure. "
            f"Key deficiencies were detected in: {deficits_text}. "
            f"Regulatory context considered: {context_excerpt}. "
            "Recommended remediation includes policy gap closure, explicit consent implementation, "
            "transparent retention disclosures, and periodic compliance monitoring."
        )
