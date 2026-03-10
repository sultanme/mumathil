from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LLMComplianceAgent:
    """Heuristic-first agent with optional LLM extension hook."""

    def analyze(self, extracted_content: dict) -> dict:
        text = extracted_content.get("clean_text", "").lower()
        forms = extracted_content.get("forms", [])

        findings = {
            "privacy_policy": any(k in text for k in ["privacy policy", "سياسة الخصوصية", "الخصوصية"]),
            "data_collection_purpose": any(k in text for k in ["purpose", "الغرض", "نستخدم البيانات", "collect"]),
            "user_consent_mechanisms": any(f.get("has_consent") for f in forms) or "consent" in text or "موافقة" in text,
            "cookie_consent_banner": any(k in text for k in ["cookie", "كوكي", "cookies settings", "cookie consent"]),
            "third_party_sharing_disclosure": any(k in text for k in ["third party", "طرف ثالث", "share data", "مشاركة البيانات"]),
            "data_retention_information": any(k in text for k in ["retention", "الاحتفاظ", "مدة الاحتفاظ", "delete"]),
        }

        evidence = {
            key: ("Found" if value else "Missing") for key, value in findings.items()
        }
        return {"findings": findings, "evidence": evidence}
