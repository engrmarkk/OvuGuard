from pydantic import BaseModel, HttpUrl, model_serializer
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from helpers import format_datetime


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanCreate(BaseModel):
    url: str
    doc_url: str
    scan_types: Optional[List[str]] = [
        "cors",
        "sql_injection",
        "xss",
        "csrf",
        "rate_limiting",
        "broken_authentication",
        "directory_traversal",
        "information_disclosure",
        "http_methods",
        "server_info",
        "backup_files",
    ]


class ScanResponse(BaseModel):
    id: str
    url: str
    status: ScanStatus
    progress: float
    created_at: datetime

    class Config:
        from_attributes = True


class Vulnerability(BaseModel):
    type: str
    severity: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    http_method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None


class ScanResultResponse(BaseModel):
    id: str
    url: str
    status: ScanStatus
    created_at: Any
    scan_duration: Optional[float] = None
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: float
    # discovered_endpoints: Optional[List[Dict[str, Any]]] = []
    vulnerabilities: Optional[List[Dict[str, Any]]] = []

    class Config:
        from_attributes = True

    @model_serializer
    def serialize_model(self):
        data = self.__dict__.copy()
        if self.created_at:
            data["created_at"] = format_datetime(self.created_at)
        return data


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


# api response
class ApiResponse(BaseModel):
    msg: str
    data: Any
    pagination: Optional[Dict[str, Any]] = None

    # if pagination is None pop it
    @model_serializer
    def serialize_model(self):
        data = self.__dict__.copy()
        if not self.pagination:
            data.pop("pagination", None)
        return data
