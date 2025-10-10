import asyncio
from fastapi import Depends
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from utils.http_client import HTTPClient
from scanners.detectors.sql_injection import SQLInjectionDetector
from scanners.detectors.xss import XSSDetector
from scanners.detectors.ssrf import SSRFDetector
from scanners.detectors.security_headers import SecurityHeadersDetector
from scanners.detectors.rate_limit import RateLimitDetector
from models import ScanResult
from schemas.scans import ScanStatus
from logger import logger
from database import get_db
from services.webhook import WebhookService
from cruds.user_crud import get_user_by_id


db = next(get_db())


class ScannerService:
    def __init__(self):
        self.http_client = HTTPClient()
        self.endpoint = []
        self.detectors = {
            "sql_injection": SQLInjectionDetector(self.http_client, self.endpoint),
            "xss": XSSDetector(self.http_client, self.endpoint),
            "ssrf": SSRFDetector(self.http_client, self.endpoint),
            "security_headers": SecurityHeadersDetector(
                self.http_client, self.endpoint
            ),
            "rate_limit": RateLimitDetector(self.http_client, self.endpoint),
        }
        self.webhook_service = WebhookService()

    async def start_scan(
        self,
        url: str,
        user_id: str,
        scan_types: List[str] = None,
        endpoints: List[Dict] = None,
    ) -> str:
        """Start a new vulnerability scan"""
        # Create scan record
        scan_record = ScanResult(
            url=url, status=ScanStatus.PENDING, progress=0.0, user_id=user_id
        )

        db.add(scan_record)
        db.commit()

        # Start background scan
        asyncio.create_task(
            self._run_scan(scan_record.id, url, user_id, scan_types, endpoints)
        )

        return scan_record.id

    async def _run_scan(
        self,
        scan_id: str,
        url: str,
        user_id: str,
        scan_types: List[str] = None,
        endpoints: List[Dict] = None,
    ):
        """Run the actual vulnerability scan in background"""
        if scan_types is None:
            scan_types = list(self.detectors.keys())

        try:
            # Update status to running
            scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
            scan_record.status = ScanStatus.RUNNING
            scan_record.discovered_endpoints = endpoints
            scan_record.progress = 10.0  # Discovery complete
            db.commit()

            logger.info(f"✅ Discovery found {len(endpoints)} endpoints")

            endpoints = await self.process_endpoints(url, endpoints)
            logger.info(f"done with join, JOINED: {endpoints}")
            self.endpoint = endpoints

            # If no endpoints found, we can still test the base URL
            if not endpoints:
                endpoints = [{"url": url, "method": "GET", "status_code": 200}]
                logger.info("ℹ️  No specific endpoints found, testing base URL")

            start_time = datetime.now()
            all_vulnerabilities = []

            # 🆕 STEP 2: RUN DETECTORS ON DISCOVERED ENDPOINTS
            total_detectors = len(scan_types)
            for i, scan_type in enumerate(scan_types):
                if scan_type in self.detectors:
                    try:
                        logger.info(f"🛡️  Running {scan_type} detection")
                        detector = self.detectors[scan_type]

                        # 🆕 Pass discovered endpoints to detectors that need them
                        if scan_type in ["sql_injection", "xss", "ssrf", "rate_limit"]:
                            # These detectors benefit from multiple endpoints
                            vulnerabilities = await self._run_detector_with_endpoints(
                                detector, endpoints, scan_type
                            )
                        else:
                            # Other detectors just use the base URL
                            vulnerabilities = await detector.detect(url)

                        all_vulnerabilities.extend(vulnerabilities)

                        # Update progress
                        progress = 10.0 + (i + 1) / total_detectors * 80.0
                        scan_record.progress = progress
                        db.commit()

                        logger.info(
                            f"✅ {scan_type} found {len(vulnerabilities)} vulnerabilities"
                        )

                    except Exception as e:
                        logger.exception("erroooooooo")
                        logger.error(f"❌ Detector {scan_type} failed: {e}")
                        # Add error as info finding
                        all_vulnerabilities.append(
                            {
                                "type": f"Scanner Error - {scan_type}",
                                "severity": "info",
                                "evidence": f"Detector failed: {str(e)}",
                                "description": f"The {scan_type} detector encountered an error.",
                                "confidence": 0.5,
                            }
                        )
                        continue

            # Calculate results
            scan_duration = (datetime.now() - start_time).total_seconds()
            metrics = self._calculate_metrics(all_vulnerabilities)

            # Update scan record with results
            scan_record.status = ScanStatus.COMPLETED
            scan_record.progress = 100.0
            scan_record.scan_duration = scan_duration
            scan_record.total_vulnerabilities = len(all_vulnerabilities)
            scan_record.critical_count = metrics["critical"]
            scan_record.high_count = metrics["high"]
            scan_record.medium_count = metrics["medium"]
            scan_record.low_count = metrics["low"]
            scan_record.security_score = metrics["security_score"]
            scan_record.vulnerabilities = all_vulnerabilities

            db.commit()

            logger.info(
                f"✅ Scan {scan_id} completed with {len(all_vulnerabilities)} vulnerabilities"
            )

            user = await get_user_by_id(db, user_id)

            if user.webhook_url:
                webhook_payload = {
                    "scan_id": scan_id,
                    "url": url,
                    "status": "completed",
                    "total_vulnerabilities": len(all_vulnerabilities),
                    "critical_count": metrics["critical"],
                    "high_count": metrics["high"],
                    "security_score": metrics["security_score"],
                    "scan_duration": scan_duration,
                    "completed_at": datetime.now().isoformat(),
                }
                await self.webhook_service.send_webhook(
                    user_id, scan_id, user.webhook_url, webhook_payload
                )

        except Exception as e:
            logger.error(f"❌ Scan {scan_id} failed: {e}")

            # Update scan record with error
            scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
            scan_record.status = ScanStatus.FAILED
            scan_record.error_message = str(e)
            db.commit()

    async def process_endpoints(
        self, base_url: str, endpoints: List[Dict]
    ) -> List[Dict]:
        """Process and normalize endpoints to ensure proper structure"""
        processed = []

        if not endpoints:
            return processed

        for endpoint in endpoints:
            try:
                # Ensure it's a dictionary
                if not isinstance(endpoint, dict):
                    logger.warning(f"Skipping non-dict endpoint: {endpoint}")
                    continue

                # Create a normalized endpoint object
                normalized_endpoint = endpoint.copy()

                normalized_endpoint["url"] = base_url + normalized_endpoint["url"]

                processed.append(normalized_endpoint)

            except Exception as e:
                logger.error(f"Error processing endpoint {endpoint}: {e}")
                continue

        logger.info(
            f"🔧 Processed {len(processed)} endpoints from {len(endpoints)} input endpoints"
        )
        return processed

    async def _run_detector_with_endpoints(
        self, detector, endpoints: List[Dict], scan_type: str
    ) -> List[Dict[str, Any]]:
        """Run detector on multiple discovered endpoints"""
        vulnerabilities = []

        for endpoint in endpoints:
            try:
                endpoint_vulns = endpoint
                if scan_type == "rate_limit":
                    # Rate limit detector needs special handling
                    endpoint_vulns = await detector.detect(endpoint["url"])
                else:
                    # Other detectors can use the endpoint URL directly
                    endpoint_vulns = await detector.detect(endpoint["url"])

                # Add endpoint context to vulnerabilities
                for vuln in endpoint_vulns:
                    vuln["endpoint"] = endpoint["url"]
                    vuln["method"] = endpoint.get("method", "GET")

                vulnerabilities.extend(endpoint_vulns)

            except Exception as e:
                logger.warning(
                    f"Detector {scan_type} failed for endpoint {endpoint['url']}: {e}"
                )
                continue

        return vulnerabilities

    def _calculate_metrics(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        counts = {severity: 0 for severity in severity_weights}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            if severity in counts:
                counts[severity] += 1

        penalty = sum(counts[sev] * weight for sev, weight in severity_weights.items())
        security_score = max(0, 100 - penalty)

        return {
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "security_score": round(security_score, 2),
        }

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
