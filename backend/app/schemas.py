from datetime import datetime
from pydantic import BaseModel, HttpUrl, Field


class ScanRequest(BaseModel):
    url: HttpUrl


class RuleResult(BaseModel):
    rule_id: str
    description: str
    passed: bool
    details: str


class ScanResponse(BaseModel):
    website: str
    compliance_score: float
    risk_level: str
    passed_rules: int
    failed_rules: int
    findings: dict
    issues: list[str]
    recommendations: list[str]
    legal_audit_report: str


class ScheduleRequest(BaseModel):
    url: HttpUrl
    interval_hours: int = Field(24, ge=1, le=720)


class ScheduleResponse(BaseModel):
    id: int
    website: str
    interval_hours: int
    active: bool


class DashboardStats(BaseModel):
    total_scans: int
    avg_compliance_score: float
    high_risk_scans: int
    recent_scans: list[dict]


class AlertResponse(BaseModel):
    website: str
    alert_type: str
    message: str
    created_at: datetime
