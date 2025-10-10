import re
from typing import List, Dict, Any
from scanners import BaseDetector
from utils.http_client import HTTPClient


class SecurityHeadersDetector(BaseDetector):
    def __init__(self, http_client, endpoints):
        super().__init__(http_client, endpoints)

    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """Check for missing or misconfigured security headers"""
        vulnerabilities = []

        try:
            response = await self.http_client.send_request("GET", url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            checks = [
                self._check_content_security_policy(headers),
                self._check_strict_transport_security(headers, url),
                self._check_x_frame_options(headers),
                self._check_x_content_type_options(headers),
                self._check_x_xss_protection(headers),
                self._check_referrer_policy(headers),
                self._check_permissions_policy(headers),
                self._check_server_header(headers),
            ]

            for check_result in checks:
                if check_result:
                    vulnerabilities.append(check_result)

        except Exception as e:
            # If we can't connect, that's a different issue
            vulnerabilities.append(
                {
                    "type": "Security Headers",
                    "severity": "medium",
                    "evidence": f"Cannot connect to target: {str(e)}",
                    "confidence": 0.9,
                }
            )

        return vulnerabilities

    def _check_content_security_policy(self, headers: Dict) -> Dict[str, Any]:
        """Check Content-Security-Policy header"""
        if "content-security-policy" not in headers:
            return {
                "type": "Missing Content-Security-Policy",
                "severity": "medium",
                "parameter": "Content-Security-Policy",
                "evidence": "Header is missing",
                "description": "Content-Security-Policy header is missing, increasing XSS risk.",
                "remediation": "Implement a strong CSP policy.",
                "confidence": 0.9,
            }

        csp = headers["content-security-policy"]

        # Check for unsafe directives
        unsafe_patterns = [r"unsafe-inline", r"unsafe-eval", r"data:", r"*"]

        for pattern in unsafe_patterns:
            if re.search(pattern, csp, re.IGNORECASE):
                return {
                    "type": "Weak Content-Security-Policy",
                    "severity": "low",
                    "parameter": "Content-Security-Policy",
                    "evidence": f"Contains unsafe directive: {pattern}",
                    "description": "CSP contains unsafe directives that reduce security effectiveness.",
                    "remediation": "Remove unsafe directives and use nonces/hashes instead.",
                    "confidence": 0.8,
                }

        return None

    def _check_strict_transport_security(
        self, headers: Dict, url: str
    ) -> Dict[str, Any]:
        """Check HSTS header"""
        if url.startswith("https") and "strict-transport-security" not in headers:
            return {
                "type": "Missing HSTS Header",
                "severity": "medium",
                "parameter": "Strict-Transport-Security",
                "evidence": "HSTS header is missing on HTTPS site",
                "description": "Missing HSTS header allows SSL stripping attacks.",
                "remediation": "Add Strict-Transport-Security header with appropriate max-age.",
                "confidence": 0.9,
            }

        if "strict-transport-security" in headers:
            hsts = headers["strict-transport-security"]
            if "max-age=0" in hsts:
                return {
                    "type": "HSTS Misconfigured",
                    "severity": "medium",
                    "parameter": "Strict-Transport-Security",
                    "evidence": "HSTS max-age is set to 0 (disabled)",
                    "description": "HSTS is configured with max-age=0, effectively disabling it.",
                    "remediation": "Set max-age to at least 31536000 (1 year).",
                    "confidence": 0.9,
                }

        return None

    def _check_x_frame_options(self, headers: Dict) -> Dict[str, Any]:
        """Check X-Frame-Options header"""
        if "x-frame-options" not in headers:
            return {
                "type": "Missing X-Frame-Options",
                "severity": "medium",
                "parameter": "X-Frame-Options",
                "evidence": "Header is missing",
                "description": "Missing X-Frame-Options makes the site vulnerable to clickjacking.",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN.",
                "confidence": 0.9,
            }

        xfo = headers["x-frame-options"].lower()
        if xfo not in ["deny", "sameorigin"]:
            return {
                "type": "Weak X-Frame-Options",
                "severity": "low",
                "parameter": "X-Frame-Options",
                "evidence": f"Unexpected value: {xfo}",
                "description": "X-Frame-Options should be set to DENY or SAMEORIGIN.",
                "remediation": "Change to X-Frame-Options: DENY",
                "confidence": 0.8,
            }

        return None

    def _check_x_content_type_options(self, headers: Dict) -> Dict[str, Any]:
        """Check X-Content-Type-Options header"""
        if "x-content-type-options" not in headers:
            return {
                "type": "Missing X-Content-Type-Options",
                "severity": "low",
                "parameter": "X-Content-Type-Options",
                "evidence": "Header is missing",
                "description": "Missing X-Content-Type-Options allows MIME type sniffing.",
                "remediation": "Add X-Content-Type-Options: nosniff",
                "confidence": 0.9,
            }

        return None

    def _check_x_xss_protection(self, headers: Dict) -> Dict[str, Any]:
        """Check X-XSS-Protection header"""
        if "x-xss-protection" not in headers:
            return {
                "type": "Missing X-XSS-Protection",
                "severity": "low",
                "parameter": "X-XSS-Protection",
                "evidence": "Header is missing",
                "description": "Missing X-XSS-Protection reduces browser XSS protection.",
                "remediation": "Add X-XSS-Protection: 1; mode=block",
                "confidence": 0.8,
            }

        return None

    def _check_referrer_policy(self, headers: Dict) -> Dict[str, Any]:
        """Check Referrer-Policy header"""
        if "referrer-policy" not in headers:
            return {
                "type": "Missing Referrer-Policy",
                "severity": "low",
                "parameter": "Referrer-Policy",
                "evidence": "Header is missing",
                "description": "Missing Referrer-Policy may leak sensitive URL parameters.",
                "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
                "confidence": 0.8,
            }

        return None

    def _check_permissions_policy(self, headers: Dict) -> Dict[str, Any]:
        """Check Permissions-Policy (formerly Feature-Policy) header"""
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            return {
                "type": "Missing Permissions-Policy",
                "severity": "low",
                "parameter": "Permissions-Policy",
                "evidence": "Header is missing",
                "description": "Missing Permissions-Policy allows unwanted browser features.",
                "remediation": "Implement Permissions-Policy to restrict browser features.",
                "confidence": 0.7,
            }

        return None

    def _check_server_header(self, headers: Dict) -> Dict[str, Any]:
        """Check for information disclosure in Server header"""
        if "server" in headers:
            server_info = headers["server"]
            # Check for specific version information
            version_patterns = [
                r"\d+\.\d+",  # Version numbers
                r"apache",
                r"nginx",
                r"iis",
                r"tomcat",  # Server types
            ]

            for pattern in version_patterns:
                if re.search(pattern, server_info, re.IGNORECASE):
                    return {
                        "type": "Information Disclosure - Server Header",
                        "severity": "low",
                        "parameter": "Server",
                        "evidence": f"Server header reveals: {server_info}",
                        "description": "Server header discloses technology and version information.",
                        "remediation": "Remove or obfuscate Server header.",
                        "confidence": 0.9,
                    }

        return None
