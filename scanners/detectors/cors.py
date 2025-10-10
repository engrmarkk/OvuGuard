import re
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from scanners import BaseDetector
from utils.http_client import HTTPClient


class CORSDetector(BaseDetector):
    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """Detect CORS misconfigurations"""
        vulnerabilities = []

        try:
            # Test various CORS scenarios
            tests = [
                self._test_null_origin(url),
                self._test_origin_reflection(url),
                self._test_weak_origin_validation(url),
                self._test_credentials_with_wildcard(url),
                self._test_preflight_requests(url),
                self._test_methods_exposure(url),
            ]

            # Run all tests
            for test in tests:
                result = await test
                if result:
                    (
                        vulnerabilities.extend(result)
                        if isinstance(result, list)
                        else vulnerabilities.append(result)
                    )

        except Exception as e:
            vulnerabilities.append(
                {
                    "type": "CORS Testing Error",
                    "severity": "low",
                    "evidence": f"CORS testing failed: {str(e)}",
                    "confidence": 0.5,
                }
            )

        return vulnerabilities

    async def _test_null_origin(self, url: str) -> List[Dict[str, Any]]:
        """Test for null origin vulnerability"""
        vulnerabilities = []

        test_origins = [
            "null",
            "https://null",
            "http://null",
        ]

        for origin in test_origins:
            try:
                response = await self.http_client.send_request(
                    "GET", url, headers={"Origin": origin}
                )

                cors_headers = self._extract_cors_headers(response)

                if self._is_origin_allowed(origin, cors_headers):
                    vulnerabilities.append(
                        {
                            "type": "CORS Misconfiguration - Null Origin",
                            "severity": "high",
                            "parameter": "Origin",
                            "payload": origin,
                            "evidence": f"Origin '{origin}' is allowed with CORS headers: {cors_headers}",
                            "description": "Null origin is allowed, which can be exploited in sandboxed iframes.",
                            "remediation": "Explicitly reject null origins in CORS validation.",
                            "confidence": 0.9,
                        }
                    )
                    break

            except Exception as e:
                continue

        return vulnerabilities

    async def _test_origin_reflection(self, url: str) -> List[Dict[str, Any]]:
        """Test for origin reflection vulnerability"""
        vulnerabilities = []

        # Test malicious origins
        malicious_origins = [
            "https://evil.com",
            "http://attacker.net",
            "https://malicious.example",
            "https://" + "a" * 100 + ".com",  # Very long domain
        ]

        for origin in malicious_origins:
            try:
                response = await self.http_client.send_request(
                    "GET", url, headers={"Origin": origin}
                )

                cors_headers = self._extract_cors_headers(response)

                # Check if the malicious origin is reflected in Access-Control-Allow-Origin
                if origin in cors_headers.get("access-control-allow-origin", ""):
                    vulnerabilities.append(
                        {
                            "type": "CORS Misconfiguration - Origin Reflection",
                            "severity": "high",
                            "parameter": "Origin",
                            "payload": origin,
                            "evidence": f"Origin '{origin}' is reflected in Access-Control-Allow-Origin",
                            "description": "Origin reflection allows any domain to access resources.",
                            "remediation": "Implement proper origin validation with an allowlist.",
                            "confidence": 0.95,
                        }
                    )
                    break

            except Exception as e:
                continue

        return vulnerabilities

    async def _test_weak_origin_validation(self, url: str) -> List[Dict[str, Any]]:
        """Test for weak origin validation (regex bypasses)"""
        vulnerabilities = []

        base_domain = urlparse(url).netloc
        domain_parts = base_domain.split(".")

        if len(domain_parts) >= 2:
            main_domain = ".".join(domain_parts[-2:])  # example.com
            subdomain = domain_parts[0] if len(domain_parts) > 2 else "www"

            # Test various bypass techniques
            bypass_origins = [
                f"https://{main_domain}.evil.com",  # Suffix attack
                f"https://evil.{main_domain}",  # Prefix attack
                f"https://{main_domain}@evil.com",  # URL encoded
                f"https://{main_domain}.com.evil.com",  # Domain confusion
                f"https://{base_domain}.evil.com",  # Full domain suffix
                f"https://{subdomain}{main_domain}.com",  # Missing dot
                f"https://{main_domain}^.evil.com",  # Special characters
            ]

            for origin in bypass_origins:
                try:
                    response = await self.http_client.send_request(
                        "GET", url, headers={"Origin": origin}
                    )

                    cors_headers = self._extract_cors_headers(response)

                    if self._is_origin_allowed(origin, cors_headers):
                        vulnerabilities.append(
                            {
                                "type": "CORS Misconfiguration - Weak Origin Validation",
                                "severity": "high",
                                "parameter": "Origin",
                                "payload": origin,
                                "evidence": f"Origin '{origin}' bypassed validation and is allowed",
                                "description": "Weak origin validation allows domain bypass attacks.",
                                "remediation": "Use strict domain comparison, not regex or contains().",
                                "confidence": 0.85,
                            }
                        )
                        break

                except Exception as e:
                    continue

        return vulnerabilities

    async def _test_credentials_with_wildcard(self, url: str) -> List[Dict[str, Any]]:
        """Test for wildcard with credentials"""
        vulnerabilities = []

        test_origin = "https://evil.com"

        try:
            response = await self.http_client.send_request(
                "GET", url, headers={"Origin": test_origin}
            )

            cors_headers = self._extract_cors_headers(response)

            allow_origin = cors_headers.get("access-control-allow-origin", "")
            allow_credentials = cors_headers.get(
                "access-control-allow-credentials", ""
            ).lower()

            if allow_origin == "*" and allow_credentials == "true":
                vulnerabilities.append(
                    {
                        "type": "CORS Misconfiguration - Wildcard with Credentials",
                        "severity": "critical",
                        "parameter": "CORS Headers",
                        "payload": "Origin: https://evil.com",
                        "evidence": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                        "description": "Wildcard origin with credentials allows any site to access authenticated content.",
                        "remediation": "Never use wildcard with credentials. Use specific origins instead.",
                        "confidence": 1.0,
                    }
                )

        except Exception as e:
            pass

        return vulnerabilities

    async def _test_preflight_requests(self, url: str) -> List[Dict[str, Any]]:
        """Test OPTIONS preflight requests"""
        vulnerabilities = []

        test_origin = "https://evil.com"
        dangerous_methods = ["PUT", "DELETE", "POST", "PATCH"]

        for method in dangerous_methods:
            try:
                response = await self.http_client.send_request(
                    "OPTIONS",
                    url,
                    headers={
                        "Origin": test_origin,
                        "Access-Control-Request-Method": method,
                    },
                )

                cors_headers = self._extract_cors_headers(response)

                # Check if preflight allows the dangerous method
                allowed_methods = cors_headers.get("access-control-allow-methods", "")
                if method in allowed_methods and self._is_origin_allowed(
                    test_origin, cors_headers
                ):
                    vulnerabilities.append(
                        {
                            "type": "CORS Misconfiguration - Dangerous Methods Allowed",
                            "severity": "medium",
                            "parameter": "Access-Control-Request-Method",
                            "payload": method,
                            "evidence": f"Preflight allows {method} method from origin {test_origin}",
                            "description": f"Dangerous HTTP method {method} is allowed via CORS.",
                            "remediation": "Restrict allowed methods to only those necessary.",
                            "confidence": 0.8,
                        }
                    )

            except Exception as e:
                continue

        return vulnerabilities

    async def _test_methods_exposure(self, url: str) -> List[Dict[str, Any]]:
        """Test for information disclosure in CORS headers"""
        vulnerabilities = []

        try:
            response = await self.http_client.send_request("OPTIONS", url)

            cors_headers = self._extract_cors_headers(response)

            # Check for excessive method exposure
            allowed_methods = cors_headers.get("access-control-allow-methods", "")
            if allowed_methods and len(allowed_methods.split(",")) > 5:
                vulnerabilities.append(
                    {
                        "type": "CORS Information Disclosure - Excessive Methods",
                        "severity": "low",
                        "parameter": "Access-Control-Allow-Methods",
                        "payload": allowed_methods,
                        "evidence": f"Exposed methods: {allowed_methods}",
                        "description": "CORS exposes excessive HTTP methods, revealing application structure.",
                        "remediation": "Only expose necessary HTTP methods.",
                        "confidence": 0.7,
                    }
                )

            # Check for excessive headers exposure
            allowed_headers = cors_headers.get("access-control-allow-headers", "")
            if allowed_headers and len(allowed_headers.split(",")) > 8:
                vulnerabilities.append(
                    {
                        "type": "CORS Information Disclosure - Excessive Headers",
                        "severity": "low",
                        "parameter": "Access-Control-Allow-Headers",
                        "payload": allowed_headers,
                        "evidence": f"Exposed headers: {allowed_headers}",
                        "description": "CORS exposes excessive HTTP headers, revealing application details.",
                        "remediation": "Only expose necessary HTTP headers.",
                        "confidence": 0.7,
                    }
                )

        except Exception as e:
            pass

        return vulnerabilities

    def _extract_cors_headers(self, response) -> Dict[str, str]:
        """Extract CORS-related headers from response"""
        cors_headers = {}
        cors_header_names = [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
        ]

        for header_name in cors_header_names:
            if header_name in response.headers:
                cors_headers[header_name] = response.headers[header_name]

        return cors_headers

    def _is_origin_allowed(self, origin: str, cors_headers: Dict[str, str]) -> bool:
        """Check if an origin is allowed based on CORS headers"""
        allow_origin = cors_headers.get("access-control-allow-origin", "")

        if allow_origin == "*":
            return True
        elif allow_origin == origin:
            return True
        elif origin in allow_origin:  # Partial match (vulnerable)
            return True

        return False

    async def _test_subdomain_takeover_via_cors(self, url: str) -> List[Dict[str, Any]]:
        """Test for potential subdomain takeover via CORS"""
        vulnerabilities = []

        base_domain = urlparse(url).netloc
        domain_parts = base_domain.split(".")

        if len(domain_parts) >= 2:
            main_domain = ".".join(domain_parts[-2:])

            # Test non-existent subdomains that might be allowed
            test_subdomains = [
                f"https://api.{main_domain}",
                f"https://dev.{main_domain}",
                f"https://staging.{main_domain}",
                f"https://test.{main_domain}",
            ]

            for origin in test_subdomains:
                try:
                    response = await self.http_client.send_request(
                        "GET", url, headers={"Origin": origin}
                    )

                    cors_headers = self._extract_cors_headers(response)

                    if self._is_origin_allowed(origin, cors_headers):
                        # Verify if the subdomain actually exists
                        try:
                            subdomain_response = await self.http_client.send_request(
                                "GET", origin
                            )
                            # If it exists, no vulnerability
                        except:
                            # Subdomain doesn't exist - potential takeover
                            vulnerabilities.append(
                                {
                                    "type": "CORS Misconfiguration - Potential Subdomain Takeover",
                                    "severity": "medium",
                                    "parameter": "Origin",
                                    "payload": origin,
                                    "evidence": f"Non-existent subdomain '{origin}' is allowed in CORS",
                                    "description": "CORS allows non-existent subdomains, enabling potential subdomain takeover attacks.",
                                    "remediation": "Validate that allowed origins actually exist and are controlled by you.",
                                    "confidence": 0.6,
                                }
                            )

                except Exception as e:
                    continue

        return vulnerabilities
