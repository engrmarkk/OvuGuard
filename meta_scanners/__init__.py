import asyncio
import json
import uuid
import yaml
import requests
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse

from database import get_db
from integrations.metasploit.services import MetasploitClient
from models import ScanResult
from datetime import datetime
import time


class SwaggerValidator:
    """Handles Swagger/OpenAPI documentation validation"""

    def __init__(self, swagger_url: str):
        self.swagger_url = swagger_url
        self.swagger_data = None
        self.endpoints = []

    async def validate(self) -> Tuple[bool, str, Optional[Dict]]:
        """
        Comprehensive Swagger/OpenAPI documentation validation

        Returns:
            Tuple[bool, str, Optional[Dict]]: (is_valid, message, swagger_data)
        """
        try:
            # Step 1: Basic accessibility check
            accessibility_result = await self._check_accessibility()
            if not accessibility_result["accessible"]:
                return False, accessibility_result["message"], None

            # Step 2: Content type and format validation
            content_result = await self._validate_content(
                accessibility_result["response"]
            )
            if not content_result["valid"]:
                return False, content_result["message"], None

            self.swagger_data = content_result["data"]

            # Step 3: OpenAPI specification validation
            spec_result = await self._validate_openapi_spec()
            if not spec_result["valid"]:
                return False, spec_result["message"], None

            # Step 4: Extract and validate endpoints
            endpoints_result = await self._validate_endpoints()
            if not endpoints_result["valid"]:
                return False, endpoints_result["message"], None

            # Step 5: Check for security definitions
            security_result = await self._check_security_definitions()
            if not security_result["valid"]:
                print(f"Security warning: {security_result['message']}")

            return True, "Swagger documentation is valid and usable", self.swagger_data

        except Exception as e:
            return False, f"Validation error: {str(e)}", None

    async def _check_accessibility(self) -> Dict[str, Any]:
        """Check if Swagger URL is accessible and returns proper response"""
        try:
            response = requests.get(
                self.swagger_url,
                timeout=10,
                headers={"User-Agent": "APISecurityScanner/1.0"},
            )

            results = {"accessible": False, "message": "", "response": response}

            if response.status_code != 200:
                results["message"] = (
                    f"HTTP {response.status_code}: Documentation not accessible"
                )
                return results

            # Check content length
            if len(response.content) == 0:
                results["message"] = "Empty response from Swagger URL"
                return results

            # Check content type
            content_type = response.headers.get("content-type", "").lower()
            if (
                "application/json" not in content_type
                and "application/yaml" not in content_type
            ):
                results["message"] = (
                    f"Invalid content type: {content_type}. Expected JSON or YAML"
                )
                return results

            results["accessible"] = True
            results["message"] = "Documentation is accessible"
            return results

        except requests.exceptions.Timeout:
            return {"accessible": False, "message": "Request timeout"}
        except requests.exceptions.ConnectionError:
            return {"accessible": False, "message": "Connection error"}
        except Exception as e:
            return {
                "accessible": False,
                "message": f"Accessibility check failed: {str(e)}",
            }

    async def _validate_content(self, response) -> Dict[str, Any]:
        """Validate the content format and structure"""
        try:
            content = response.content.decode("utf-8")
            data = None

            # Try parsing as JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Try parsing as YAML
                try:
                    data = yaml.safe_load(content)
                except yaml.YAMLError:
                    return {
                        "valid": False,
                        "message": "Content is neither valid JSON nor YAML",
                    }

            if not isinstance(data, dict):
                return {
                    "valid": False,
                    "message": "Swagger content must be a JSON object",
                }

            # Check for required OpenAPI fields
            required_fields = ["openapi", "info", "paths"]
            missing_fields = [field for field in required_fields if field not in data]

            if missing_fields:
                return {
                    "valid": False,
                    "message": f"Missing required OpenAPI fields: {', '.join(missing_fields)}",
                }

            # Validate OpenAPI version
            openapi_version = data.get("openapi", "")
            if not openapi_version.startswith(("2.", "3.")):
                return {
                    "valid": False,
                    "message": f"Unsupported OpenAPI version: {openapi_version}",
                }

            return {"valid": True, "message": "Content format is valid", "data": data}

        except Exception as e:
            return {"valid": False, "message": f"Content validation failed: {str(e)}"}

    async def _validate_openapi_spec(self) -> Dict[str, Any]:
        """Validate against OpenAPI specification schema"""
        try:
            openapi_version = self.swagger_data.get("openapi", "")

            # Basic schema validation
            if not self._validate_basic_schema():
                return {"valid": False, "message": "Invalid OpenAPI schema structure"}

            # Validate info section
            info = self.swagger_data.get("info", {})
            if not info.get("title") or not info.get("version"):
                return {
                    "valid": False,
                    "message": "Info section must contain title and version",
                }

            # Validate paths section
            paths = self.swagger_data.get("paths", {})
            if not paths or not isinstance(paths, dict):
                return {
                    "valid": False,
                    "message": "Paths section must be a non-empty object",
                }

            return {"valid": True, "message": "OpenAPI specification is valid"}

        except Exception as e:
            return {
                "valid": False,
                "message": f"Specification validation failed: {str(e)}",
            }

    async def _validate_endpoints(self) -> Dict[str, Any]:
        """Extract and validate API endpoints"""
        try:
            endpoints = self._extract_endpoints()

            if not endpoints:
                return {
                    "valid": False,
                    "message": "No API endpoints found in documentation",
                }

            # Check if endpoints have meaningful paths
            invalid_paths = []
            for endpoint in endpoints:
                path = endpoint.get("path", "")
                if not path or path == "/":
                    invalid_paths.append(path)

            if invalid_paths:
                return {
                    "valid": False,
                    "message": f"Found {len(invalid_paths)} invalid endpoint paths",
                }

            # Check for parameter definitions
            endpoints_without_params = []
            for endpoint in endpoints:
                if not endpoint.get("parameters") and endpoint["method"] in [
                    "POST",
                    "PUT",
                    "PATCH",
                ]:
                    endpoints_without_params.append(
                        f"{endpoint['method']} {endpoint['path']}"
                    )

            if endpoints_without_params:
                print(
                    f"Warning: {len(endpoints_without_params)} endpoints without parameter definitions"
                )

            self.endpoints = endpoints
            return {
                "valid": True,
                "message": f"Found {len(endpoints)} valid endpoints",
                "endpoints_count": len(endpoints),
            }

        except Exception as e:
            return {"valid": False, "message": f"Endpoint validation failed: {str(e)}"}

    async def _check_security_definitions(self) -> Dict[str, Any]:
        """Check for security definitions and authentication"""
        try:
            security_schemes = self.swagger_data.get("components", {}).get(
                "securitySchemes", {}
            )
            security = self.swagger_data.get("security", [])

            results = {
                "valid": True,
                "message": "",
                "has_authentication": False,
                "security_schemes": list(security_schemes.keys()),
            }

            if security_schemes:
                results["has_authentication"] = True
                results["message"] = (
                    f"Security schemes defined: {', '.join(security_schemes.keys())}"
                )
            else:
                results["message"] = "No security schemes defined - API may be open"

            # Check if global security is defined
            if security:
                results["message"] += " | Global security requirements defined"
            else:
                results["message"] += " | No global security requirements"

            return results

        except Exception as e:
            return {"valid": False, "message": f"Security check failed: {str(e)}"}

    def _validate_basic_schema(self) -> bool:
        """Basic OpenAPI schema validation"""
        required_sections = ["openapi", "info", "paths"]
        return all(section in self.swagger_data for section in required_sections)

    def _extract_endpoints(self) -> List[Dict]:
        """Enhanced endpoint extraction with better parameter handling"""
        endpoints = []

        if "paths" not in self.swagger_data:
            return endpoints

        for path, methods in self.swagger_data["paths"].items():
            for method, details in methods.items():
                if method.upper() in [
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                ]:

                    # Extract parameters with more detail
                    parameters = []
                    for param in details.get("parameters", []):
                        param_info = {
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "type": param.get("schema", {}).get(
                                "type", param.get("type", "string")
                            ),
                            "required": param.get("required", False),
                        }
                        parameters.append(param_info)

                    # Extract request body for POST/PUT/PATCH
                    request_body = {}
                    if "requestBody" in details and method.upper() in [
                        "POST",
                        "PUT",
                        "PATCH",
                    ]:
                        content = details["requestBody"].get("content", {})
                        for content_type, schema in content.items():
                            request_body = {
                                "content_type": content_type,
                                "schema": schema.get("schema", {}),
                            }
                            break  # Take first content type for now

                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "parameters": parameters,
                        "request_body": request_body,
                        "summary": details.get("summary", ""),
                        "operation_id": details.get("operationId", ""),
                        "tags": details.get("tags", []),
                    }
                    endpoints.append(endpoint)

        return endpoints

    async def get_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        is_valid, message, swagger_data = await self.validate()

        report = {
            "valid": is_valid,
            "message": message,
            "swagger_url": self.swagger_url,
            "openapi_version": (
                swagger_data.get("openapi", "Unknown") if swagger_data else "Unknown"
            ),
            "title": (
                swagger_data.get("info", {}).get("title", "Unknown")
                if swagger_data
                else "Unknown"
            ),
            "endpoints_count": len(self.endpoints),
            "has_authentication": False,
            "security_schemes": [],
            "warnings": [],
            "errors": [] if is_valid else [message],
        }

        if swagger_data:
            security_info = await self._check_security_definitions()
            report["has_authentication"] = security_info["has_authentication"]
            report["security_schemes"] = security_info["security_schemes"]

        return report


class ScanResultManager:
    """Manages scan results in the database"""

    def __init__(self):
        self.db = next(get_db())

    def create_scan(self, url: str, user_id: str = None) -> ScanResult:
        """Create a new scan record in database"""
        scan_result = ScanResult(
            url=url,
            status="pending",
            progress=0.0,
            user_id=user_id,
            discovered_endpoints=[],
            vulnerabilities=[],
            total_vulnerabilities=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            security_score=100.0,
            scan_duration=0.0,
        )

        self.db.add(scan_result)
        self.db.commit()
        self.db.refresh(scan_result)
        return scan_result

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        progress: float = None,
        error_message: str = None,
    ) -> None:
        """Update scan status and progress"""
        scan = self.db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = status
            if progress is not None:
                scan.progress = progress
            if error_message:
                scan.error_message = error_message
            self.db.commit()

    def add_discovered_endpoints(self, scan_id: str, endpoints: List[Dict]) -> None:
        """Add discovered endpoints to scan results"""
        scan = self.db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.discovered_endpoints = endpoints
            self.db.commit()

    def add_vulnerability(self, scan_id: str, vulnerability: Dict) -> None:
        """Add a vulnerability finding to scan results"""
        scan = self.db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            # Add to vulnerabilities list
            current_vulns = scan.vulnerabilities or []
            current_vulns.append(vulnerability)
            scan.vulnerabilities = current_vulns

            # Update counters based on severity
            severity = vulnerability.get("severity", "low").lower()
            if severity == "critical":
                scan.critical_count += 1
            elif severity == "high":
                scan.high_count += 1
            elif severity == "medium":
                scan.medium_count += 1
            else:
                scan.low_count += 1

            # Update total count
            scan.total_vulnerabilities = len(current_vulns)

            # Recalculate security score (0-100, higher is better)
            scan.security_score = self._calculate_security_score(scan)

            self.db.commit()

    def _calculate_security_score(self, scan: ScanResult) -> float:
        """Calculate security score based on vulnerabilities"""
        base_score = 100.0
        penalties = {"critical": 20, "high": 10, "medium": 5, "low": 1}

        total_penalty = (
            scan.critical_count * penalties["critical"]
            + scan.high_count * penalties["high"]
            + scan.medium_count * penalties["medium"]
            + scan.low_count * penalties["low"]
        )

        return max(0, base_score - total_penalty)

    def complete_scan(self, scan_id: str, scan_duration: float) -> None:
        """Mark scan as completed"""
        scan = self.db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = "completed"
            scan.progress = 100.0
            scan.scan_duration = scan_duration
            self.db.commit()


class VulnerabilityTester:
    """Handles vulnerability testing for API endpoints"""

    def __init__(
        self,
        api_url: str,
        metasploit_client: MetasploitClient,
        result_manager: ScanResultManager,
    ):
        self.api_url = api_url.rstrip("/")
        self.metasploit = metasploit_client
        self.result_manager = result_manager

    async def test_endpoint(self, scan_id: str, endpoint: Dict) -> None:
        """Test a single endpoint for multiple vulnerabilities"""
        tests = [
            (self.test_sql_injection, "SQL Injection"),
            (self.test_xss, "XSS"),
            (self.test_csrf, "CSRF"),
            (self.test_rate_limiting, "Rate Limiting"),
            (self.test_nosql_injection, "NoSQL Injection"),
            (self.test_authentication, "Authentication"),
            (self.test_authorization, "Authorization"),
        ]

        for test_func, test_name in tests:
            try:
                await test_func(scan_id, endpoint)
            except Exception as e:
                print(f"Error in {test_name} test for {endpoint['path']}: {str(e)}")

    async def test_sql_injection(self, scan_id: str, endpoint: Dict) -> None:
        """Test for SQL injection using Metasploit"""
        target_url = f"{self.api_url}{endpoint['path']}"

        try:
            # Send to Metasploit for SQLi scanning
            results = self.metasploit.scan_sql_injection(
                target_url, endpoint["method"], endpoint.get("parameters", [])
            )

            if results.get("vulnerable", False):
                vulnerability = {
                    "type": "sql_injection",
                    "severity": "high",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "evidence": results.get("evidence", "SQL injection detected"),
                    "payload": results.get("payload", ""),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                self.result_manager.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            print(f"SQL injection test failed for {endpoint['path']}: {str(e)}")

    async def test_xss(self, scan_id: str, endpoint: Dict) -> None:
        """Test for Cross-Site Scripting"""
        target_url = f"{self.api_url}{endpoint['path']}"

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
        ]

        for payload in xss_payloads:
            try:
                result = await self._send_payload(endpoint, payload)
                if payload in str(result.content):
                    vulnerability = {
                        "type": "xss",
                        "severity": "medium",
                        "endpoint": endpoint["path"],
                        "method": endpoint["method"],
                        "evidence": "XSS payload reflected in response",
                        "payload": payload,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    self.result_manager.add_vulnerability(scan_id, vulnerability)
                    break  # Found one, no need to test more payloads
            except Exception as e:
                continue

    async def test_csrf(self, scan_id: str, endpoint: Dict) -> None:
        """Test for CSRF vulnerabilities"""
        try:
            response = requests.request(
                endpoint["method"], f"{self.api_url}{endpoint['path']}"
            )

            csrf_indicators = ["csrf", "xsrf", "token"]
            has_protection = any(
                indicator in key.lower()
                for key in response.headers
                for indicator in csrf_indicators
            )

            if not has_protection and endpoint["method"] in [
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
            ]:
                vulnerability = {
                    "type": "csrf",
                    "severity": "medium",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "evidence": "No CSRF protection headers found",
                    "protection_headers": dict(response.headers),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                self.result_manager.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            print(f"CSRF test failed for {endpoint['path']}: {str(e)}")

    async def test_rate_limiting(self, scan_id: str, endpoint: Dict) -> None:
        """Test for rate limiting"""
        try:
            target_url = f"{self.api_url}{endpoint['path']}"
            rapid_requests = []

            # Send 10 rapid requests
            for i in range(10):
                response = requests.request(endpoint["method"], target_url)
                rapid_requests.append(
                    {
                        "request": i + 1,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                    }
                )

            # Check for rate limiting responses (429 status code)
            rate_limited = any(req["status_code"] == 429 for req in rapid_requests)

            if not rate_limited:
                vulnerability = {
                    "type": "rate_limiting",
                    "severity": "low",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "evidence": "No rate limiting detected after 10 rapid requests",
                    "requests": rapid_requests,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                self.result_manager.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            print(f"Rate limiting test failed for {endpoint['path']}: {str(e)}")

    async def test_nosql_injection(self, scan_id: str, endpoint: Dict) -> None:
        """Test for NoSQL injection"""
        nosql_payloads = [
            '{"$ne": "invalid"}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$gt": ""}',
        ]

        for payload in nosql_payloads:
            try:
                result = await self._send_json_payload(endpoint, payload)
                if result.status_code == 500:
                    vulnerability = {
                        "type": "nosql_injection",
                        "severity": "high",
                        "endpoint": endpoint["path"],
                        "method": endpoint["method"],
                        "evidence": "Server error on NoSQL operator",
                        "payload": payload,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    self.result_manager.add_vulnerability(scan_id, vulnerability)
                    break
            except Exception as e:
                continue

    async def test_authentication(self, scan_id: str, endpoint: Dict) -> None:
        """Test for authentication bypass attempts"""
        # This is a simplified example - expand based on your needs
        if endpoint.get("requires_auth", False):
            # Test without authentication
            try:
                response = requests.request(
                    endpoint["method"], f"{self.api_url}{endpoint['path']}"
                )
                if response.status_code == 200:
                    vulnerability = {
                        "type": "authentication_bypass",
                        "severity": "critical",
                        "endpoint": endpoint["path"],
                        "method": endpoint["method"],
                        "evidence": "Endpoint accessible without authentication",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    self.result_manager.add_vulnerability(scan_id, vulnerability)
            except Exception as e:
                print(f"Authentication test failed for {endpoint['path']}: {str(e)}")

    async def test_authorization(self, scan_id: str, endpoint: Dict) -> None:
        """Test for authorization issues"""
        # Placeholder for authorization tests
        # You can implement IDOR testing, privilege escalation, etc.
        pass

    async def _send_payload(self, endpoint: Dict, payload: str) -> requests.Response:
        """Send a payload to the endpoint"""
        url = f"{self.api_url}{endpoint['path']}"

        test_data = {}
        for param in endpoint.get("parameters", []):
            if param["in"] == "query":
                test_data[param["name"]] = payload
            elif param["in"] == "body":
                test_data[param["name"]] = payload

        return requests.request(
            endpoint["method"],
            url,
            json=test_data if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
            params=test_data if endpoint["method"] in ["GET", "DELETE"] else None,
        )

    async def _send_json_payload(
        self, endpoint: Dict, payload: str
    ) -> requests.Response:
        """Send JSON payload to the endpoint"""
        url = f"{self.api_url}{endpoint['path']}"

        return requests.request(
            endpoint["method"],
            url,
            json=(
                json.loads(payload)
                if endpoint["method"] in ["POST", "PUT", "PATCH"]
                else None
            ),
        )


class APIScanner:
    """Main API Scanner class that orchestrates the scanning process"""

    def __init__(self, api_url: str, swagger_url: str):
        self.api_url = api_url
        self.swagger_url = swagger_url
        self.endpoints = []

        # Initialize components
        self.validator = SwaggerValidator(swagger_url)
        self.metasploit = MetasploitClient()
        self.result_manager = ScanResultManager()
        self.tester = VulnerabilityTester(api_url, self.metasploit, self.result_manager)

    async def start_scan(self, user_id: str = None) -> Tuple[str, str]:
        """
        Start comprehensive vulnerability scanning

        Returns:
            Tuple[str, str]: (scan_id, status_message)
        """
        start_time = time.time()
        scan_result = self.result_manager.create_scan(self.api_url, user_id)
        scan_id = str(scan_result.id)

        try:
            # Update status to running
            self.result_manager.update_scan_status(scan_id, "running", 10)

            # Step 1: Validate Swagger documentation
            is_valid, message, swagger_data = await self.validator.validate()

            if not is_valid:
                self.result_manager.update_scan_status(
                    scan_id, "failed", error_message=message
                )
                return scan_id, f"Scan failed: {message}"

            self.result_manager.update_scan_status(scan_id, "running", 30)

            # Get endpoints from validator
            self.endpoints = self.validator.endpoints

            # Save discovered endpoints
            self.result_manager.add_discovered_endpoints(scan_id, self.endpoints)
            self.result_manager.update_scan_status(scan_id, "running", 50)

            # Step 2: Test each endpoint for vulnerabilities
            total_endpoints = len(self.endpoints)
            for index, endpoint in enumerate(self.endpoints):
                await self.tester.test_endpoint(scan_id, endpoint)

                # Update progress
                progress = 50 + (index / total_endpoints) * 50
                self.result_manager.update_scan_status(scan_id, "running", progress)

            # Step 3: Complete the scan
            scan_duration = time.time() - start_time
            self.result_manager.complete_scan(scan_id, scan_duration)

            return scan_id, "Scan completed successfully"

        except Exception as e:
            error_msg = f"Scan failed with error: {str(e)}"
            self.result_manager.update_scan_status(
                scan_id, "failed", error_message=error_msg
            )
            return scan_id, error_msg

    async def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get current scan status and results"""
        scan = (
            self.result_manager.db.query(ScanResult)
            .filter(ScanResult.id == scan_id)
            .first()
        )
        if scan:
            return {
                "id": str(scan.id),
                "url": scan.url,
                "status": scan.status,
                "progress": scan.progress,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "security_score": scan.security_score,
                "scan_duration": scan.scan_duration,
                "error_message": scan.error_message,
                "discovered_endpoints": scan.discovered_endpoints,
                "vulnerabilities": scan.vulnerabilities,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
            }
        return None

    async def validate_swagger(self) -> Tuple[bool, str, Optional[Dict]]:
        """Validate Swagger documentation"""
        return await self.validator.validate()

    async def get_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        return await self.validator.get_validation_report()
