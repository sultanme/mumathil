# Mumtathil AI Compliance Backend

FastAPI backend that upgrades Mumtathil into a production-style AI compliance platform.

## Features
- Multi-page website crawler agent (`CrawlerAgent`)
- Content extraction and policy section detection (`PolicyExtractionAgent`)
- AI policy analysis agent (`LLMComplianceAgent`)
- PDPL rule engine with weighted compliance scoring (`RuleEngineAgent`)
- Legal-style audit writer (`LegalAuditorAgent`)
- Regulation knowledge ingestion + retrieval (RAG service)
- Scan scheduling and recurring monitoring
- Alerting (dashboard + optional email)
- SQLite persistence for scans, reports, schedules, and alerts

## Run
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Key APIs for existing frontend
- `POST /api/v1/scans` -> Run scanner from WebScanner page
- `GET /api/v1/dashboard` -> Dashboard statistics and recent scans
- `GET /api/v1/alerts` -> Alert feed for compliance drops and high-risk scans
- `POST /api/v1/schedules` -> Enable recurring scans
- `POST /api/v1/regulations/upload` -> Upload PDPL/SDAIA docs for RAG
