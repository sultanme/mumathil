from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(String(512), index=True, nullable=False)
    status = Column(String(32), default="completed", nullable=False)
    compliance_score = Column(Float, nullable=False)
    risk_level = Column(String(32), nullable=False)
    findings = Column(JSON, nullable=False)
    issues = Column(JSON, nullable=False)
    recommendations = Column(JSON, nullable=False)
    legal_audit_report = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(String(512), nullable=False)
    interval_hours = Column(Integer, default=24, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(String(512), nullable=False)
    alert_type = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    metadata = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RegulationDocument(Base):
    __tablename__ = "regulation_documents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    chunks = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
