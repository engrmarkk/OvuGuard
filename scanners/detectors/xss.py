import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseDetector
from environmentals import SCANNER_RATE_LIMIT_DELAY


class XSSDetector(BaseDetector):
    def __init__(self, http_client, endpoints):
        super().__init__(http_client, endpoints)
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]

    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        vulnerabilities = []

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.payloads:
                try:
                    test_params = query_params.copy()
                    test_params[param] = [payload]

                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(
                        (
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            test_query,
                            parsed_url.fragment,
                        )
                    )

                    response = await self.http_client.send_request("GET", test_url)

                    if self._is_payload_reflected(payload, response.text):
                        vulnerabilities.append(
                            {
                                "type": "Cross-Site Scripting (XSS)",
                                "severity": "high",
                                "parameter": param,
                                "payload": payload,
                                "evidence": "Payload reflected without proper encoding",
                                "http_method": "GET",
                                "url": test_url,
                                "status_code": response.status_code,
                                "confidence": 0.8,
                            }
                        )

                    await asyncio.sleep(SCANNER_RATE_LIMIT_DELAY)

                except Exception as e:
                    continue

        return vulnerabilities

    def _is_payload_reflected(self, payload: str, response_text: str) -> bool:
        if payload in response_text:
            return True

        encoded_payloads = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;"),
        ]

        return any(encoded in response_text for encoded in encoded_payloads)
