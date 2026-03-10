from __future__ import annotations

from sqlalchemy.orm import Session

from app.agents.crawler_agent import CrawlerAgent
from app.agents.content_extractor import PolicyExtractionAgent
from app.agents.policy_analysis_agent import LLMComplianceAgent
from app.agents.rule_engine import RuleEngineAgent
from app.agents.report_generator import ReportAgent
from app.models import RegulationDocument
from app.services.legal_auditor_agent import LegalAuditorAgent
from app.services.rag_service import RegulationRAGService


class ComplianceOrchestrator:
    def __init__(self, rules_path: str):
        self.crawler = CrawlerAgent()
        self.extractor = PolicyExtractionAgent()
        self.analyzer = LLMComplianceAgent()
        self.rule_engine = RuleEngineAgent(rules_path)
        self.report_agent = ReportAgent()
        self.legal_auditor = LegalAuditorAgent()
        self.rag_service = RegulationRAGService()

    async def run_scan(self, db: Session, url: str) -> dict:
        crawled = await self.crawler.crawl(url)
        merged_text = "\n".join(p.text for p in crawled)
        merged_html = "\n".join(p.html for p in crawled)

        extracted = self.extractor.extract(merged_html)
        if merged_text:
            extracted["clean_text"] = f"{extracted['clean_text']} {merged_text}"

        analysis = self.analyzer.analyze(extracted)
        evaluation = self.rule_engine.evaluate(analysis)
        report = self.report_agent.generate(url, evaluation)

        all_chunks = []
        for doc in db.query(RegulationDocument).all():
            all_chunks.extend(doc.chunks)
        retrieved_context = self.rag_service.retrieve("PDPL consent and retention obligations", all_chunks)

        legal_report = self.legal_auditor.generate_audit(
            website=url,
            findings=analysis["findings"],
            evaluation=evaluation,
            regulatory_context=retrieved_context,
        )

        report["findings"] = analysis["findings"]
        report["legal_audit_report"] = legal_report
        return report
