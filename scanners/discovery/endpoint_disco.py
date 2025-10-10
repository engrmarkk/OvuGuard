import asyncio
from typing import List, Dict, Any
from urllib.parse import urljoin
from utils.http_client import HTTPClient


class EndpointDiscovery:
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.common_endpoints = [
            # Authentication endpoints
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/info",
            "/version",
            # Documentation
            "/docs",
            "/swagger",
            "/openapi",
        ]

    async def discover_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover existing endpoints with their supported methods"""
        discovered = []

        for endpoint in self.common_endpoints:
            test_url = urljoin(base_url, endpoint)

            # Test common HTTP methods
            for method in ["GET", "POST"]:
                try:
                    response = await self.http_client.send_request(
                        method,
                        test_url,
                        json={"test": "data"} if method == "POST" else None,
                    )

                    # Consider endpoint valid if we get a non-4xx/5xx response
                    if response.status_code < 400:
                        discovered.append(
                            {
                                "url": test_url,
                                "method": method,
                                "status_code": response.status_code,
                                "path": endpoint,
                            }
                        )
                        print(
                            f"✅ Discovered: {method} {test_url} - Status: {response.status_code}"
                        )

                except Exception as e:
                    # Endpoint doesn't exist or has issues
                    continue

        return discovered
