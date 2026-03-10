from __future__ import annotations

import re
from bs4 import BeautifulSoup


class PolicyExtractionAgent:
    POLICY_SECTION_MARKERS = [
        "privacy", "cookie", "retention", "consent", "third party", "data collection", "purpose",
        "سياسة", "الخصوصية", "الكوكيز", "الاحتفاظ", "موافقة",
    ]

    def extract(self, html: str) -> dict:
        soup = BeautifulSoup(html, "lxml")
        for el in soup(["script", "style", "noscript"]):
            el.decompose()

        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
        sections = [line for line in re.split(r"(?<=[\.!؟])\s+", text) if self._is_policy_line(line)]

        forms = []
        for form in soup.find_all("form"):
            form_text = re.sub(r"\s+", " ", form.get_text(" ", strip=True).lower())
            forms.append(
                {
                    "action": form.get("action"),
                    "method": form.get("method", "get").lower(),
                    "has_consent": any(k in form_text for k in ["consent", "agree", "privacy", "أوافق", "موافقة"]),
                }
            )

        return {
            "clean_text": text,
            "policy_sections": sections[:100],
            "forms": forms,
            "has_forms": len(forms) > 0,
        }

    def _is_policy_line(self, line: str) -> bool:
        l = line.lower()
        return any(marker in l for marker in self.POLICY_SECTION_MARKERS)
