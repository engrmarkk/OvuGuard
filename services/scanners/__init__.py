# import asyncio
# from fastapi import Depends
# from datetime import datetime
from typing import List, Dict, Any, Optional

# from sqlalchemy.orm import Session

# from utils.http_client import HTTPClient
# from scanners.detectors.sql_injection import SQLInjectionDetector
# from scanners.detectors.xss import XSSDetector
# from scanners.detectors.ssrf import SSRFDetector
# from scanners.detectors.security_headers import SecurityHeadersDetector
# from scanners.detectors.rate_limit import RateLimitDetector
from models import ScanResult

# from schemas.scans import ScanStatus
from logger import logger
from database import get_db
from services.webhook import WebhookService

# from cruds.user_crud import get_user_by_id


db = next(get_db())


class ScannerService:
    def __init__(self):
        # self.http_client = HTTPClient()
        # self.endpoint = []
        # self.detectors = {
        #     "sql_injection": SQLInjectionDetector(self.http_client, self.endpoint),
        #     "xss": XSSDetector(self.http_client, self.endpoint),
        #     "ssrf": SSRFDetector(self.http_client, self.endpoint),
        #     "security_headers": SecurityHeadersDetector(
        #         self.http_client, self.endpoint
        #     ),
        #     "rate_limit": RateLimitDetector(self.http_client, self.endpoint),
        # }
        self.webhook_service = WebhookService()

    def get_scan_status(self, scan_id: str, user_id: str) -> Optional[ScanResult]:
        """Get scan status by ID"""
        return (
            db.query(ScanResult)
            .filter(ScanResult.id == scan_id, ScanResult.user_id == user_id)
            .first()
        )

    def get_recent_scans(self, limit: int = 10) -> List[ScanResult]:
        """Get recent scan results"""
        return (
            db.query(ScanResult)
            .order_by(ScanResult.created_at.desc())
            .limit(limit)
            .all()
        )

    # return the paginated object of scans for a user desc order created_at
    async def get_all_user_scans(self, page: int, per_page: int, user_id: str):
        return (
            db.query(ScanResult)
            .filter(ScanResult.user_id == user_id)
            .order_by(ScanResult.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

    # get total scans, total vulnerabilitoes, total security scores, total apis scanned
    # get recent scans (api url, date, score, vulnerabilites(high, medium, low), status)
    async def get_user_scan_stats(self, user_id: str):
        # Fetch all user scans in one query
        scans = (
            db.query(ScanResult)
            .filter(ScanResult.user_id == user_id)
            .order_by(ScanResult.created_at.desc())
            .all()
        )

        if not scans:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "total_security_scores": 0,
                "total_apis_scanned": 0,
                "recent_scans": [],
            }

        total_scans = len(scans)
        # total_vulnerabilities = sum(len(scan.vulnerabilities or []) for scan in scans)
        total_security_score = (
            sum(scan.security_score for scan in scans) / total_scans
            if total_scans > 0
            else 0
        )
        recent_scans = scans[:10]

        return {
            "total_scans": total_scans,
            "total_vulnerabilities": sum(scan.total_vulnerabilities for scan in scans),
            "total_security_scores": total_security_score,
            "total_apis_scanned": total_scans,  # same meaning, avoid duplicate query
            "recent_scans": [scan.to_overview() for scan in recent_scans],
        }
