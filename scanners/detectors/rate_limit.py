import asyncio
import time
from typing import List, Dict, Any, Optional
from scanners import BaseDetector
from utils.http_client import HTTPClient
from logger import logger
from urllib.parse import urljoin


# class RateLimitDetector(BaseDetector):
#     async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
#         """Test for rate limiting protection"""
#         vulnerabilities = []

#         # Test endpoints that should be protected
#         test_endpoints = [
#             "/api/v1/auth/login",
#             "/api/v1/auth/register",
#         ]

#         for endpoint in test_endpoints:
#             test_url = f"{url.rstrip('/')}{endpoint}"
#             result = await self._test_rate_limit(test_url)
#             logger.info(f"RESULT: {result}")
#             if result:
#                 vulnerabilities.append(result)

#         return vulnerabilities

#     async def _test_rate_limit(self, url: str) -> Dict[str, Any]:
#         """Test a specific endpoint for rate limiting"""
#         try:
#             # First, make a successful request to understand normal behavior
#             initial_response = await self.http_client.send_request(
#                 "POST", url, json={"email": "test@test.com", "password": "test"}
#             )

#             # Make rapid consecutive requests to trigger rate limiting
#             requests_made = 0
#             start_time = time.time()

#             for i in range(20):  # Make 20 rapid requests
#                 try:
#                     response = await self.http_client.send_request(
#                         "POST",
#                         url,
#                         json={"email": f"test{i}@test.com", "password": f"test{i}"},
#                     )
#                     requests_made += 1

#                     # No delay between requests

#                 except Exception as e:
#                     # Request failed - might be due to rate limiting
#                     break

#             elapsed_time = time.time() - start_time
#             request_rate = requests_made / elapsed_time if elapsed_time > 0 else 0

#             # Analyze results
#             if (
#                 requests_made >= 15 and request_rate > 5
#             ):  # More than 5 requests per second
#                 return {
#                     "type": "Missing Rate Limiting",
#                     "severity": "medium",
#                     "parameter": f"Endpoint: {url}",
#                     "evidence": f"Made {requests_made} requests in {elapsed_time:.2f}s ({request_rate:.1f} req/s) without blocking",
#                     "description": "Endpoint lacks rate limiting protection, making it vulnerable to brute force attacks.",
#                     "remediation": "Implement rate limiting with tools like Redis, rate limiting middleware, or WAF.",
#                     "confidence": 0.8,
#                 }

#             # Test with different HTTP methods
#             methods_to_test = ["POST", "GET", "PUT"]
#             for method in methods_to_test:
#                 rapid_responses = []
#                 for j in range(10):
#                     try:
#                         if method in ["POST", "PUT"]:
#                             resp = await self.http_client.send_request(
#                                 method, url, json={"email": f"test{j}@test.com", "password": f"test{j}"}
#                             )
#                         else:
#                             resp = await self.http_client.send_request(method, url)
#                         rapid_responses.append(resp.status_code)
#                     except:
#                         rapid_responses.append(0)

#                 # Check if all requests succeeded (no 429s)
#                 if all(status != 429 for status in rapid_responses):
#                     return {
#                         "type": "Missing Rate Limiting",
#                         "severity": "medium",
#                         "parameter": f"Endpoint: {url} (Method: {method})",
#                         "evidence": f"10 rapid {method} requests completed without rate limiting (no 429 responses)",
#                         "description": f"{method} requests to this endpoint are not rate limited.",
#                         "remediation": "Implement comprehensive rate limiting for all HTTP methods.",
#                         "confidence": 0.7,
#                     }

#         except Exception as e:
#             # Endpoint might not exist or have different behavior
#             pass

#         return None

#     async def _test_brute_force_vulnerability(self, url: str) -> Dict[str, Any]:
#         """Test specifically for login brute force vulnerability"""
#         try:
#             # Test common passwords rapidly
#             common_passwords = ["123456", "password", "admin", "test", "1234"]
#             successful_attempts = 0

#             for password in common_passwords:
#                 try:
#                     response = await self.http_client.send_request(
#                         "POST", url, json={"username": "admin", "password": password}
#                     )

#                     # Check if request was successful (not necessarily correct login)
#                     if response.status_code == 200:
#                         successful_attempts += 1

#                 except Exception:
#                     continue

#             if successful_attempts == len(common_passwords):
#                 return {
#                     "type": "Brute Force Vulnerability",
#                     "severity": "high",
#                     "parameter": f"Login endpoint: {url}",
#                     "evidence": f"All {successful_attempts} rapid login attempts completed without blocking",
#                     "description": "Login endpoint is vulnerable to brute force attacks due to missing rate limiting.",
#                     "remediation": "Implement account lockout after failed attempts and strong rate limiting.",
#                     "confidence": 0.9,
#                 }

#         except Exception as e:
#             pass

#         return None


class RateLimitDetector(BaseDetector):
    def __init__(self, http_client, endpoints):
        super().__init__(http_client, endpoints)

    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """Test for rate limiting protection with proper endpoint discovery"""
        vulnerabilities = []

        # First, discover actual endpoints that exist
        existing_endpoints = self.endpoints
        logger.info(f"Existing endpoints: {existing_endpoints}")

        if not existing_endpoints:
            vulnerabilities.append(
                {
                    "type": "Rate Limit Testing - No Endpoints Found",
                    "severity": "info",
                    "evidence": "No testable endpoints found for rate limit testing",
                    "description": "Could not find suitable endpoints to test for rate limiting.",
                    "confidence": 0.5,
                }
            )
            return vulnerabilities

        # Test each existing endpoint
        for endpoint in existing_endpoints:
            result = await self._test_endpoint_rate_limit(
                endpoint["url"], endpoint["method"]
            )
            logger.info(f"RESULT: {result}")
            if result:
                vulnerabilities.append(result)

        return vulnerabilities

    async def _test_endpoint_rate_limit(
        self, url: str, method: str
    ) -> Optional[Dict[str, Any]]:
        """Test a specific endpoint for rate limiting with proper logic"""
        print(f"🔍 Testing rate limiting for {method} {url}")

        try:
            # Step 1: Make initial request to understand normal behavior
            initial_response = await self._make_test_request(url, method)

            if not initial_response:
                return None

            # Step 2: Make rapid consecutive requests to trigger rate limiting
            requests_made = 0
            rate_limited_requests = 0
            start_time = time.time()

            # Make multiple rapid requests
            for i in range(15):  # Reduced from 20 to be less aggressive
                try:
                    response = await self._make_test_request(url, method, i)

                    if response:
                        requests_made += 1

                        # Check for rate limiting (429 status code)
                        if response.status_code == 429:
                            rate_limited_requests += 1
                            print(
                                f"⚠️  Rate limit triggered on request {i+1} - Status: 429"
                            )

                    # Very small delay to make requests rapid but not overwhelming
                    await asyncio.sleep(0.1)

                except Exception as e:
                    # Request failed - might be due to rate limiting or other issues
                    continue

            elapsed_time = time.time() - start_time

            # Step 3: Analyze results with proper logic
            if requests_made == 0:
                return None

            request_rate = requests_made / elapsed_time if elapsed_time > 0 else 0

            print(f"📊 Rate limit test results for {method} {url}:")
            print(f"   Requests made: {requests_made}")
            print(f"   Rate limited: {rate_limited_requests}")
            print(f"   Time: {elapsed_time:.2f}s")
            print(f"   Rate: {request_rate:.1f} req/s")

            # Logic to determine if rate limiting is effective
            if rate_limited_requests > 0:
                # Rate limiting IS working
                return {
                    "type": "Rate Limiting Implemented",
                    "severity": "info",
                    "parameter": f"Endpoint: {url}",
                    "evidence": f"Rate limiting detected: {rate_limited_requests}/{requests_made} requests blocked with 429 status",
                    "description": "Endpoint has rate limiting protection in place.",
                    "remediation": "Current rate limiting configuration appears adequate.",
                    "confidence": 0.9,
                }
            elif (
                requests_made >= 10 and request_rate > 2
            ):  # More than 2 requests per second
                # No rate limiting detected
                return {
                    "type": "Missing Rate Limiting",
                    "severity": "medium",
                    "parameter": f"Endpoint: {url}",
                    "evidence": f"Made {requests_made} requests in {elapsed_time:.2f}s ({request_rate:.1f} req/s) without rate limiting (no 429 responses)",
                    "description": "Endpoint lacks rate limiting protection, making it vulnerable to brute force attacks.",
                    "remediation": "Implement rate limiting with tools like Redis, rate limiting middleware, or WAF.",
                    "confidence": 0.8,
                }
            else:
                # Inconclusive - not enough successful requests to test properly
                return {
                    "type": "Rate Limit Testing Inconclusive",
                    "severity": "info",
                    "parameter": f"Endpoint: {url}",
                    "evidence": f"Only {requests_made} successful requests made, insufficient for conclusive rate limit testing",
                    "description": "Could not properly test rate limiting due to endpoint restrictions.",
                    "remediation": "Ensure endpoints are accessible for security testing.",
                    "confidence": 0.5,
                }

        except Exception as e:
            print(f"❌ Error testing rate limit for {url}: {e}")
            return None

    async def _make_test_request(
        self, url: str, method: str, request_id: int = 0
    ) -> Optional[Any]:
        """Make a test request with appropriate data"""
        try:
            if method in ["POST", "PUT", "PATCH"]:
                # For mutation methods, use test data
                test_data = {
                    "username": f"testuser{request_id}",
                    "password": f"testpass{request_id}",
                    "email": f"test{request_id}@example.com",
                }
                return await self.http_client.send_request(method, url, json=test_data)
            else:
                # For GET methods, just request the endpoint
                return await self.http_client.send_request(method, url)
        except Exception as e:
            return None

    async def _test_brute_force_vulnerability(
        self, url: str
    ) -> Optional[Dict[str, Any]]:
        """Test specifically for login brute force vulnerability"""
        try:
            # Test common passwords rapidly
            common_passwords = ["123456", "password", "admin", "test", "1234"]
            successful_attempts = 0
            rate_limited_attempts = 0

            for i, password in enumerate(common_passwords):
                try:
                    response = await self.http_client.send_request(
                        "POST", url, json={"username": "admin", "password": password}
                    )

                    # Count successful requests (not necessarily successful logins)
                    if response.status_code != 429:
                        successful_attempts += 1
                    else:
                        rate_limited_attempts += 1

                    # Small delay between attempts
                    await asyncio.sleep(0.2)

                except Exception as e:
                    continue

            print(
                f"🔐 Brute force test: {successful_attempts} successful, {rate_limited_attempts} rate limited"
            )

            if (
                successful_attempts == len(common_passwords)
                and rate_limited_attempts == 0
            ):
                return {
                    "type": "Brute Force Vulnerability",
                    "severity": "high",
                    "parameter": f"Login endpoint: {url}",
                    "evidence": f"All {successful_attempts} rapid login attempts completed without rate limiting",
                    "description": "Login endpoint is vulnerable to brute force attacks due to missing rate limiting.",
                    "remediation": "Implement account lockout after failed attempts and strong rate limiting.",
                    "confidence": 0.9,
                }
            elif rate_limited_attempts > 0:
                return {
                    "type": "Brute Force Protection Active",
                    "severity": "info",
                    "parameter": f"Login endpoint: {url}",
                    "evidence": f"Rate limiting blocked {rate_limited_attempts}/{len(common_passwords)} login attempts",
                    "description": "Login endpoint has brute force protection via rate limiting.",
                    "remediation": "Current protection appears adequate.",
                    "confidence": 0.8,
                }

        except Exception as e:
            print(f"❌ Error testing brute force vulnerability: {e}")

        return None
