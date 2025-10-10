from database import Base
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Float,
    Text,
    JSON,
    Enum as SQLAlchemyEnum,
)

# from sqlalchemy.orm import relationship
from helpers import format_datetime
from datetime import datetime, timedelta
from enum import Enum
from models.model_similarities import TimestampMixin, UUIDPrimaryKeyMixin


class ScanResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_results"
    url = Column(Text, nullable=False)
    # Scan status
    status = Column(
        String(20), default="pending"
    )  # pending, running, completed, failed
    progress = Column(Float, default=0.0)  # 0-100

    # Results
    total_vulnerabilities = Column(Integer, default=0)
    discovered_endpoints = Column(JSON, default=list)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    security_score = Column(Float, default=100.0)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)

    # Technical details
    scan_duration = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)

    # Raw results
    vulnerabilities = Column(JSON, default=list)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "created_at": format_datetime(self.created_at),
            "status": self.status,
            "progress": self.progress,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "security_score": self.security_score,
            "scan_duration": self.scan_duration,
            "error_message": self.error_message,
            "vulnerabilities": self.vulnerabilities,
        }

    def to_overview(self):
        return {
            "id": self.id,
            "url": self.url,
            "created_at": format_datetime(self.created_at),
            "status": self.status,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "security_score": self.security_score,
        }


class WebhookLogs(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "webhook_logs"
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    scan_id = Column(String, ForeignKey("scan_results.id"), nullable=False)
    webhook_url = Column(Text, nullable=False)
    status_code = Column(Integer)
    response = Column(Text)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "webhook_url": self.webhook_url,
            "status_code": self.status_code,
            "response": self.response,
        }
