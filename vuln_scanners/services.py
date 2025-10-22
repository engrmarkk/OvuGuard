# services.py
import requests
import time
import json
from typing import Dict, List, Any, Tuple
from .base import BaseScanner, ScanConfig, SwaggerValidator
from logger import logger


class CORSScanner(BaseScanner):
    """Scan for CORS misconfigurations using actual endpoints"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for CORS misconfigurations...")

        # Test endpoints from Swagger + common endpoints
        test_endpoints = self._get_test_endpoints()

        for endpoint in test_endpoints:
            self._test_endpoint_cors(endpoint)

        return self.get_scan_results()

    def _get_test_endpoints(self) -> List[Dict]:
        """Get endpoints to test for CORS"""
        endpoints = self.endpoints.copy()

        # Add common API endpoints if not in Swagger
        common_endpoints = ["/", "/api", "/api/v1", "/graphql", "/rest"]
        for path in common_endpoints:
            if not any(ep["path"] == path for ep in endpoints):
                endpoints.append({"path": path, "method": "GET"})

        return endpoints[:10]  # Test first 10 endpoints

    def _test_endpoint_cors(self, endpoint: Dict):
        """Test a single endpoint for CORS misconfigurations"""
        url = f"{self.config.target_url}{endpoint['path']}"
        test_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            self.config.target_url,
            "https://example.com",
        ]

        for origin in test_origins:
            try:
                response = requests.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": endpoint["method"],
                    },
                    timeout=self.config.timeout,
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")
                acam = response.headers.get("Access-Control-Allow-Methods", "")

                # Analyze CORS configuration
                if acao == "*" and acac.lower() == "true":
                    self.save_finding(
                        "cors_misconfiguration",
                        "CORS allows any origin with credentials",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} | Origin: {origin} | ACAO: {acao} | ACAC: {acac}",
                        endpoint,
                        "high",
                        "high",
                    )
                elif acao == "*":
                    self.save_finding(
                        "cors_misconfiguration",
                        "CORS allows any origin",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} | Origin: {origin} | ACAO: {acao}",
                        endpoint,
                        "medium",
                        "high",
                    )
                elif origin in acao:
                    self.save_finding(
                        "cors_reflection",
                        "CORS reflects origin",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} | Origin: {origin} | ACAO: {acao}",
                        endpoint,
                        "medium",
                        "high",
                    )

            except Exception as e:
                continue


class SQLInjectionScanner(BaseScanner):
    """SQL Injection scanner using actual parameters from Swagger"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for SQL Injection vulnerabilities...")

        # Use Metasploit modules for SQL injection
        self._run_metasploit_sql_scans()

        # Manual testing with actual parameters
        self._manual_sql_tests()

        return self.get_scan_results()

    def _run_metasploit_sql_scans(self):
        """Run Metasploit SQL injection modules on endpoints"""
        sql_modules = [
            "scanner/http/blind_sql_query",
            "scanner/http/error_sql_injection",
            "scanner/http/sql_injection",
        ]

        for endpoint in self.endpoints[:5]:  # Test first 5 endpoints
            for module_name in sql_modules:
                url = f"{self.config.target_url}{endpoint['path']}"
                result = self.run_metasploit_module(module_name, url)

                if "job_id" in result:
                    self.save_finding(
                        "sql_injection",
                        f"SQL injection scan initiated with {module_name}",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} | Module: {module_name} | Job: {result['job_id']}",
                        endpoint,
                        "medium",
                        "medium",
                    )

    def _manual_sql_tests(self):
        """Manual SQL injection tests using actual parameters"""
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' ORDER BY 1--",
            "1' UNION SELECT database()--",
        ]

        for endpoint in self.endpoints:
            if endpoint["method"] in ["GET", "POST", "PUT"]:
                self._test_endpoint_sql(endpoint, sql_payloads)

    def _test_endpoint_sql(self, endpoint: Dict, payloads: List[str]):
        """Test a single endpoint for SQL injection"""
        url = f"{self.config.target_url}{endpoint['path']}"

        # Test each parameter with SQL payloads
        for param in endpoint.get("parameters", []):
            if param["in"] in ["query", "body"]:  # Test query and body params
                for payload in payloads[:3]:  # Test first 3 payloads per parameter
                    try:
                        if endpoint["method"] == "GET":
                            response = requests.get(
                                url,
                                params={param["name"]: payload},
                                timeout=self.config.timeout,
                            )
                        else:
                            response = requests.request(
                                endpoint["method"],
                                url,
                                json={param["name"]: payload},
                                timeout=self.config.timeout,
                            )

                        if self._detect_sql_errors(response):
                            self.save_finding(
                                "sql_injection",
                                "Potential SQL injection vulnerability",
                                f"Endpoint: {endpoint['method']} {endpoint['path']} | Parameter: {param['name']} | Payload: {payload} | Response: {response.status_code}",
                                endpoint,
                                "high",
                                "medium",
                            )

                    except Exception as e:
                        continue

    def _detect_sql_errors(self, response) -> bool:
        """Detect SQL errors in response"""
        sql_indicators = [
            "sql",
            "mysql",
            "postgresql",
            "oracle",
            "database",
            "query",
            "syntax error",
            "union",
            "select",
            "from",
            "where",
            "column",
            "table",
            "insert",
            "update",
            "delete",
        ]

        response_text = response.text.lower()
        return any(indicator in response_text for indicator in sql_indicators)


class XSSScanner(BaseScanner):
    """XSS scanner using actual parameters from Swagger"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for XSS vulnerabilities...")

        # Use Metasploit XSS modules
        self._run_metasploit_xss_scans()

        # Manual XSS testing with actual parameters
        self._manual_xss_tests()

        return self.get_scan_results()

    def _run_metasploit_xss_scans(self):
        """Run Metasploit XSS scanning modules"""
        xss_modules = [
            "scanner/http/http_traversal",  # Can detect XSS in some cases
        ]

        for endpoint in self.endpoints[:3]:
            if endpoint["method"] in ["GET", "POST"]:
                url = f"{self.config.target_url}{endpoint['path']}"
                for module_name in xss_modules:
                    result = self.run_metasploit_module(module_name, url)
                    if "job_id" in result:
                        self.save_finding(
                            "xss",
                            f"XSS scan initiated with {module_name}",
                            f"Endpoint: {endpoint['method']} {endpoint['path']}",
                            endpoint,
                            "medium",
                            "medium",
                        )

    def _manual_xss_tests(self):
        """Manual XSS testing using actual parameters"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
        ]

        for endpoint in self.endpoints:
            if endpoint["method"] in ["GET", "POST", "PUT"]:
                self._test_endpoint_xss(endpoint, xss_payloads)

    def _test_endpoint_xss(self, endpoint: Dict, payloads: List[str]):
        """Test a single endpoint for XSS"""
        url = f"{self.config.target_url}{endpoint['path']}"

        for param in endpoint.get("parameters", []):
            if param["in"] in ["query", "body"]:
                for payload in payloads[:3]:
                    try:
                        if endpoint["method"] == "GET":
                            response = requests.get(
                                url,
                                params={param["name"]: payload},
                                timeout=self.config.timeout,
                            )
                        else:
                            response = requests.request(
                                endpoint["method"],
                                url,
                                json={param["name"]: payload},
                                timeout=self.config.timeout,
                            )

                        # Check if payload is reflected without encoding
                        if payload in response.text:
                            self.save_finding(
                                "xss",
                                "XSS payload reflected without encoding",
                                f"Endpoint: {endpoint['method']} {endpoint['path']} | Parameter: {param['name']} | Payload: {payload}",
                                endpoint,
                                "medium",
                                "high",
                            )

                    except Exception as e:
                        continue


class CSRFScanner(BaseScanner):
    """CSRF vulnerability scanner"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for CSRF vulnerabilities...")

        # Get endpoints from Swagger that might be state-changing
        state_changing_endpoints = [
            e
            for e in self.endpoints
            if e["method"] in ["POST", "PUT", "DELETE", "PATCH"]
        ]

        for endpoint in state_changing_endpoints[:10]:  # Test first 10
            self._test_endpoint_csrf(endpoint)

        return self.get_scan_results()

    def _test_endpoint_csrf(self, endpoint: Dict):
        """Test a single endpoint for CSRF protection"""
        url = f"{self.config.target_url}{endpoint['path']}"

        try:
            # Check for CSRF protection
            response = requests.request(
                endpoint["method"], url, timeout=self.config.timeout
            )

            # Look for CSRF tokens in common places
            csrf_indicators = ["csrf", "xsrf", "token"]
            has_protection = any(
                indicator in key.lower()
                for key in response.headers
                for indicator in csrf_indicators
            )

            # Also check response body for tokens
            if not has_protection:
                response_text_lower = response.text.lower()
                has_protection = any(
                    indicator in response_text_lower for indicator in csrf_indicators
                )

            if not has_protection:
                self.save_finding(
                    "csrf",
                    "Missing CSRF protection",
                    f"Endpoint: {endpoint['method']} {endpoint['path']} - No CSRF tokens detected in headers or response",
                    endpoint,
                    "medium",
                    "medium",
                )

        except Exception as e:
            logger.exception(f"CSRF test failed for {endpoint['path']}: {e}")


class RateLimitScanner(BaseScanner):
    """Rate limiting vulnerability scanner"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for rate limiting...")

        # Find authentication endpoints
        auth_endpoints = [
            e
            for e in self.endpoints
            if any(
                keyword in e["path"].lower()
                for keyword in ["auth", "login", "token", "password"]
            )
        ]

        if not auth_endpoints:
            # Use common auth endpoints if not in Swagger
            auth_endpoints = [{"path": "/api/v1/auth/login", "method": "POST"}]

        for endpoint in auth_endpoints[:2]:  # Test first 2 auth endpoints
            self._test_endpoint_rate_limit(endpoint)

        return self.get_scan_results()

    def _test_endpoint_rate_limit(self, endpoint: Dict):
        """Test rate limiting on a specific endpoint"""
        url = f"{self.config.target_url}{endpoint['path']}"

        try:
            rapid_requests = []

            # Send 20 rapid requests
            for i in range(20):
                start_time = time.time()
                if endpoint["method"] in ["POST", "PUT", "PATCH"]:
                    response = requests.request(
                        endpoint["method"],
                        url,
                        json={"username": f"test{i}", "password": "test"},
                        timeout=self.config.timeout,
                    )
                else:
                    response = requests.request(
                        endpoint["method"],
                        url,
                        params={"user": f"test{i}"},
                        timeout=self.config.timeout,
                    )

                response_time = time.time() - start_time

                rapid_requests.append(
                    {
                        "request": i + 1,
                        "status_code": response.status_code,
                        "response_time": response_time,
                        "headers": dict(response.headers),
                    }
                )

            # Check for rate limiting
            rate_limited = any(req["status_code"] == 429 for req in rapid_requests)
            response_times = [req["response_time"] for req in rapid_requests]
            avg_response_time = sum(response_times) / len(response_times)

            if not rate_limited and avg_response_time < 1.0:
                self.save_finding(
                    "rate_limiting",
                    "No rate limiting detected on authentication endpoint",
                    f"Endpoint: {endpoint['method']} {endpoint['path']} | 20 rapid requests - No 429 responses, avg response time: {avg_response_time:.2f}s",
                    endpoint,
                    "low",
                    "high",
                )

        except Exception as e:
            logger.exception(f"Rate limit test failed for {endpoint['path']}: {e}")


class BrokenAuthScanner(BaseScanner):
    """Broken authentication scanner"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for broken authentication...")

        # Find authentication endpoints
        auth_endpoints = [
            e
            for e in self.endpoints
            if any(
                keyword in e["path"].lower() for keyword in ["auth", "login", "token"]
            )
        ]

        if not auth_endpoints:
            # Use common auth endpoints if not in Swagger
            auth_endpoints = [
                {"path": "/api/v1/auth/login", "method": "POST", "parameters": []},
                {"path": "/auth/login", "method": "POST", "parameters": []},
                {"path": "/login", "method": "POST", "parameters": []},
            ]

        for endpoint in auth_endpoints:
            self._test_endpoint_auth(endpoint)

        return self.get_scan_results()

    def _test_endpoint_auth(self, endpoint: Dict):
        """Test authentication endpoint for vulnerabilities"""
        url = f"{self.config.target_url}{endpoint['path']}"

        try:
            # Test with empty credentials
            response = requests.request(
                endpoint["method"], url, json={}, timeout=self.config.timeout
            )

            # Check if it returns success with empty credentials
            if response.status_code == 200:
                response_data = (
                    response.json()
                    if response.headers.get("content-type", "").startswith(
                        "application/json"
                    )
                    else {}
                )
                if isinstance(response_data, dict) and any(
                    key in response_data for key in ["token", "access_token", "success"]
                ):
                    self.save_finding(
                        "broken_authentication",
                        "Authentication accepts empty credentials",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} - Returns success with empty credentials",
                        endpoint,
                        "critical",
                        "high",
                    )

            # Test authentication bypass patterns
            bypass_payloads = [
                {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
                {"username": "admin", "password": "admin"},
                {"username": "' OR '1'='1", "password": "anything"},
                {"username": "admin", "password": ""},
                {"username": "", "password": "admin"},
            ]

            for payload in bypass_payloads:
                response = requests.request(
                    endpoint["method"], url, json=payload, timeout=self.config.timeout
                )
                if response.status_code == 200:
                    response_data = (
                        response.json()
                        if response.headers.get("content-type", "").startswith(
                            "application/json"
                        )
                        else {}
                    )
                    if isinstance(response_data, dict) and any(
                        key in response_data
                        for key in ["token", "access_token", "success"]
                    ):
                        self.save_finding(
                            "broken_authentication",
                            "Authentication bypass possible",
                            f"Endpoint: {endpoint['method']} {endpoint['path']} - Bypassed with payload: {json.dumps(payload)}",
                            endpoint,
                            "critical",
                            "medium",
                        )
                        break

        except Exception as e:
            logger.exception(f"Auth test failed for {endpoint['path']}: {e}")


class DirectoryTraversalScanner(BaseScanner):
    """Directory traversal scanner using Metasploit"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for directory traversal vulnerabilities...")

        # Use Metasploit directory traversal modules
        traversal_modules = [
            "scanner/http/dir_scanner",
            "scanner/http/brute_dirs",
            "scanner/http/backup_file",
            "scanner/http/files_dir",
            "scanner/http/http_traversal",
        ]

        for endpoint in self.endpoints[:3]:
            url = f"{self.config.target_url}{endpoint['path']}"
            for module_name in traversal_modules:
                result = self.run_metasploit_module(module_name, url)
                if "job_id" in result:
                    self.save_finding(
                        "directory_traversal",
                        f"Directory traversal scan initiated with {module_name}",
                        f"Endpoint: {endpoint['method']} {endpoint['path']} | Module: {module_name}",
                        endpoint,
                        "medium",
                        "medium",
                    )

        return self.get_scan_results()


class ServerInfoScanner(BaseScanner):
    """Server information disclosure scanner"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for server information disclosure...")

        # Use Metasploit server info modules
        info_modules = [
            "scanner/http/http_version",
            "scanner/http/http_header",
            "scanner/http/robots_txt",
            "scanner/http/title",
        ]

        for endpoint in self.endpoints[:2]:
            url = f"{self.config.target_url}{endpoint['path']}"
            for module_name in info_modules:
                result = self.run_metasploit_module(module_name, url)
                if "job_id" in result:
                    self.save_finding(
                        "information_disclosure",
                        f"Server info scan initiated with {module_name}",
                        f"Endpoint: {endpoint['method']} {endpoint['path']}",
                        endpoint,
                        "low",
                        "medium",
                    )

        # Manual header checking
        self._check_headers()

        return self.get_scan_results()

    def _check_headers(self):
        """Manually check for information disclosure in headers"""
        for endpoint in self.endpoints[:3]:
            try:
                url = f"{self.config.target_url}{endpoint['path']}"
                response = requests.get(url, timeout=self.config.timeout)

                info_headers = [
                    "Server",
                    "X-Powered-By",
                    "X-AspNet-Version",
                    "X-Runtime",
                ]
                for header in info_headers:
                    if header in response.headers:
                        self.save_finding(
                            "information_disclosure",
                            f"Information disclosure in {header} header",
                            f"Endpoint: {endpoint['method']} {endpoint['path']} | {header}: {response.headers[header]}",
                            endpoint,
                            "low",
                            "high",
                        )

            except Exception as e:
                continue


class HTTPMethodsScanner(BaseScanner):
    """HTTP methods scanner"""

    def scan(self) -> Dict[str, Any]:
        logger.info("Scanning for HTTP methods vulnerabilities...")

        # Use Metasploit HTTP methods module
        methods_module = "scanner/http/options"

        for endpoint in self.endpoints[:5]:
            url = f"{self.config.target_url}{endpoint['path']}"
            result = self.run_metasploit_module(methods_module, url)
            if "job_id" in result:
                self.save_finding(
                    "http_methods",
                    "HTTP methods scan initiated",
                    f"Endpoint: {endpoint['method']} {endpoint['path']}",
                    endpoint,
                    "low",
                    "medium",
                )

        # Manual HTTP method testing
        self._test_dangerous_methods()

        return self.get_scan_results()

    def _test_dangerous_methods(self):
        """Test for dangerous HTTP methods"""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

        for endpoint in self.endpoints:
            url = f"{self.config.target_url}{endpoint['path']}"
            for method in dangerous_methods:
                try:
                    response = requests.request(
                        method, url, timeout=self.config.timeout
                    )
                    if response.status_code not in [
                        405,
                        501,
                    ]:  # If not "Method Not Allowed"
                        self.save_finding(
                            "http_methods",
                            f"Dangerous HTTP method {method} allowed",
                            f"Endpoint: {endpoint['path']} | Method: {method} | Status: {response.status_code}",
                            endpoint,
                            "medium",
                            "high",
                        )
                except Exception as e:
                    continue


class APISecurityScanner:
    """Main API security scanner that orchestrates all scans"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.swagger_validator = (
            SwaggerValidator(config.swagger_url) if config.swagger_url else None
        )
        self.endpoints = []
        self.scanners = {}
        self.scan_results = {}

    def validate_and_extract_endpoints(self) -> Tuple[bool, str]:
        """Validate Swagger doc and extract endpoints"""
        if not self.swagger_validator:
            self.endpoints = self._get_default_endpoints()
            return True, "No Swagger URL provided, using default endpoints"

        is_valid, message, endpoints = self.swagger_validator.validate_and_parse()

        if is_valid:
            self.endpoints = endpoints
            return (
                True,
                f"Valid Swagger documentation - extracted {len(endpoints)} endpoints",
            )
        else:
            self.endpoints = self._get_default_endpoints()
            return False, f"{message} - using default endpoints"

    def _get_default_endpoints(self) -> List[Dict]:
        """Get default endpoints when no Swagger is available"""
        return [
            {"path": "/", "method": "GET", "parameters": []},
            {"path": "/api", "method": "GET", "parameters": []},
            {"path": "/api/v1", "method": "GET", "parameters": []},
            {"path": "/graphql", "method": "POST", "parameters": []},
            {"path": "/rest", "method": "GET", "parameters": []},
            {
                "path": "/api/v1/auth/login",
                "method": "POST",
                "parameters": [
                    {"name": "username", "in": "body", "type": "string"},
                    {"name": "password", "in": "body", "type": "string"},
                ],
            },
        ]

    def initialize_scanners(self):
        """Initialize only the scanners specified in config.scan_types"""
        scanner_map = {
            "cors": CORSScanner,
            "sql_injection": SQLInjectionScanner,
            "xss": XSSScanner,
            "csrf": CSRFScanner,
            "rate_limiting": RateLimitScanner,
            "broken_authentication": BrokenAuthScanner,
            "directory_traversal": DirectoryTraversalScanner,
            "information_disclosure": ServerInfoScanner,
            "http_methods": HTTPMethodsScanner,
        }

        # ONLY initialize scanners that are in the scan_types list
        for scan_type in self.config.scan_types:
            if scan_type in scanner_map:
                self.scanners[scan_type] = scanner_map[scan_type](
                    self.config, self.endpoints
                )
                logger.info(f"Initialized {scan_type} scanner")
            else:
                logger.info(f"Unknown scan type: {scan_type}")

    def run_scan(self) -> Dict[str, Any]:
        """Run comprehensive API security scan - ONLY runs specified scan types"""
        logger.info(f"Starting API security scan for {self.config.target_url}")
        logger.info(f"Scan types: {', '.join(self.config.scan_types)}")

        # Validate and extract endpoints
        is_valid, message = self.validate_and_extract_endpoints()
        logger.info(f"{message}")

        # Initialize ONLY the specified scanners
        logger.info(f"\nInitializing scanners...")
        self.initialize_scanners()

        start_time = time.time()
        all_vulnerabilities = []

        # Run ONLY the scanners that were initialized (from scan_types)
        logger.info(f"\nRunning scans...")
        for scan_type, scanner in self.scanners.items():
            logger.info(f"Running {scan_type} scan...")

            try:
                result = scanner.scan()
                self.scan_results[scan_type] = result

                if "vulnerabilities" in result:
                    all_vulnerabilities.extend(result["vulnerabilities"])

                vuln_count = len(result.get("vulnerabilities", []))
                logger.info(f"{scan_type} completed - Found {vuln_count} issues")

            except Exception as e:
                logger.exception(f"{scan_type} failed: {e}")
                self.scan_results[scan_type] = {"error": str(e)}

        scan_duration = time.time() - start_time

        # Calculate overall metrics
        critical = len([v for v in all_vulnerabilities if v["severity"] == "critical"])
        high = len([v for v in all_vulnerabilities if v["severity"] == "high"])
        medium = len([v for v in all_vulnerabilities if v["severity"] == "medium"])
        low = len([v for v in all_vulnerabilities if v["severity"] == "low"])

        security_score = max(
            0, 100 - (critical * 20 + high * 10 + medium * 5 + low * 1)
        )

        return {
            "url": self.config.target_url,
            "status": "completed",
            "progress": 100.0,
            "total_vulnerabilities": len(all_vulnerabilities),
            "discovered_endpoints": self.endpoints,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "security_score": security_score,
            "scan_duration": scan_duration,
            "error_message": None,
            "vulnerabilities": all_vulnerabilities,
            "user_id": self.config.user_id,
        }
