from __future__ import annotations

from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db, SessionLocal
from app.models import RegulationDocument, Scan, ScanSchedule, Alert
from app.schemas import ScanRequest, ScanResponse, ScheduleRequest, ScheduleResponse, DashboardStats, AlertResponse
from app.services.alert_service import AlertService
from app.services.compliance_service import ComplianceOrchestrator
from app.services.rag_service import RegulationRAGService

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Mumtathil AI Compliance Platform", version="1.0.0")
orchestrator = ComplianceOrchestrator(str(Path(__file__).resolve().parents[1] / "rules" / "rules.json"))
alert_service = AlertService()
rag_service = RegulationRAGService()
scheduler = BackgroundScheduler()
scheduler.start()


async def _execute_scan(db: Session, url: str) -> dict:
    report = await orchestrator.run_scan(db, url)

    previous = db.query(Scan).filter(Scan.website == url).order_by(Scan.created_at.desc()).first()
    scan = Scan(
        website=url,
        compliance_score=report["compliance_score"],
        risk_level=report["risk_level"],
        findings=report["findings"],
        issues=report["issues"],
        recommendations=report["recommendations"],
        legal_audit_report=report["legal_audit_report"],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    if previous and report["compliance_score"] < previous.compliance_score:
        alert_service.create_alert(
            db,
            website=url,
            alert_type="compliance_drop",
            message=f"Compliance score dropped from {previous.compliance_score} to {report['compliance_score']}",
            metadata={"previous": previous.compliance_score, "current": report["compliance_score"]},
        )

    if report["risk_level"] == "high":
        alert_service.create_alert(
            db,
            website=url,
            alert_type="high_risk",
            message="High risk compliance status detected.",
            metadata={"score": report["compliance_score"]},
        )

    return report


@app.post("/api/v1/scans", response_model=ScanResponse)
async def scan_website(payload: ScanRequest, db: Session = Depends(get_db)):
    return await _execute_scan(db, str(payload.url))


@app.get("/api/v1/dashboard", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    avg_score = db.query(func.avg(Scan.compliance_score)).scalar() or 0.0
    high_risk = db.query(func.count(Scan.id)).filter(Scan.risk_level == "high").scalar() or 0
    recent = db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    recent_scans = [
        {
            "website": s.website,
            "score": s.compliance_score,
            "risk_level": s.risk_level,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent
    ]
    return DashboardStats(total_scans=total_scans, avg_compliance_score=round(float(avg_score), 2), high_risk_scans=high_risk, recent_scans=recent_scans)


@app.get("/api/v1/alerts", response_model=list[AlertResponse])
def list_alerts(db: Session = Depends(get_db)):
    rows = db.query(Alert).order_by(Alert.created_at.desc()).limit(100).all()
    return [AlertResponse(website=r.website, alert_type=r.alert_type, message=r.message, created_at=r.created_at) for r in rows]


@app.post("/api/v1/schedules", response_model=ScheduleResponse)
def create_schedule(payload: ScheduleRequest, db: Session = Depends(get_db)):
    schedule = ScanSchedule(website=str(payload.url), interval_hours=payload.interval_hours, active=True)
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    def scheduled_job(schedule_id: int):
        local_db = SessionLocal()
        try:
            sched = local_db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id, ScanSchedule.active.is_(True)).first()
            if not sched:
                return
            import asyncio

            asyncio.run(_execute_scan(local_db, sched.website))
            sched.last_run_at = datetime.utcnow()
            local_db.commit()
        finally:
            local_db.close()

    scheduler.add_job(scheduled_job, "interval", hours=payload.interval_hours, args=[schedule.id], id=f"schedule-{schedule.id}", replace_existing=True)
    return ScheduleResponse(id=schedule.id, website=schedule.website, interval_hours=schedule.interval_hours, active=schedule.active)


@app.post("/api/v1/regulations/upload")
async def upload_regulation_document(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    chunks = rag_service.chunk_text(content)
    row = RegulationDocument(filename=file.filename or "document.txt", content=content, chunks=chunks)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "filename": row.filename, "chunks": len(chunks)}


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "mumtathil-ai-compliance-backend"}
