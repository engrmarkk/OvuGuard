from vuln_scanners.services import APISecurityScanner, SwaggerValidator
from vuln_scanners.base import ScanConfig
from database import get_db
from models import ScanResult
from logger import logger

db = next(get_db())


class VulnServices:
    def __init__(self):
        pass

    def check_valid_doc(self, swagger_url):
        validator = SwaggerValidator(swagger_url)
        res, _, _ = validator.validate_and_parse()
        return res

    def _start(self, url, swagger_url, scan_types, user_id):
        # Configuration - User specifies exactly which scans to run
        config = ScanConfig(
            target_url=url,
            swagger_url=swagger_url,
            scan_types=scan_types,
            user_id=user_id,
        )

        # Initialize and run scanner - ONLY runs specified scan_types
        scanner = APISecurityScanner(config)
        scan_result = scanner.run_scan()

        try:
            scan_record = ScanResult(**scan_result)
            db.add(scan_record)
            db.commit()
            logger.info(f"Scan results saved with ID: {scan_record.id}")
        except Exception as e:
            logger.exception(f"Failed to save results: {e}")
            db.rollback()
        finally:
            db.close()

        returned_dict = {
            "url": scan_result["url"],
            "status": scan_result["status"],
            "progress": scan_result["progress"],
            "total_vulnerabilities": scan_result["total_vulnerabilities"],
            "discovered_endpoints": scan_result["discovered_endpoints"],
            "critical_count": scan_result["critical_count"],
            "high_count": scan_result["high_count"],
            "medium_count": scan_result["medium_count"],
            "low_count": scan_result["low_count"],
            "security_score": scan_result["security_score"],
            "scan_duration": scan_result["scan_duration"],
            "error_message": scan_result["error_message"],
            "vulnerabilities": scan_result["vulnerabilities"],
            "user_id": scan_result["user_id"],
        }
        logger.info(f"Scan completed with result: {returned_dict}")
        return returned_dict
