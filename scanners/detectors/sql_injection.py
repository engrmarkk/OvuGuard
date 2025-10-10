import re
import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners import BaseDetector
from environmentals import SCANNER_RATE_LIMIT_DELAY


class SQLInjectionDetector(BaseDetector):
    def __init__(self, http_client, endpoints):
        super().__init__(http_client, endpoints)
        self.payloads = [
            "'",
            "''",
            "`",
            "``",
            '"',
            '""',
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
        ]
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"Microsoft SQL Server",
            r"ODBC Driver",
        ]

    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        vulnerabilities = []

        # Test URL parameters
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

                    if self._contains_sql_errors(response.text):
                        vulnerabilities.append(
                            {
                                "type": "SQL Injection",
                                "severity": "critical",
                                "parameter": param,
                                "payload": payload,
                                "evidence": self._extract_evidence(response.text),
                                "http_method": "GET",
                                "url": test_url,
                                "status_code": response.status_code,
                                "confidence": 0.9,
                            }
                        )

                    await asyncio.sleep(SCANNER_RATE_LIMIT_DELAY)

                except Exception as e:
                    continue

        return vulnerabilities

    def _contains_sql_errors(self, text: str) -> bool:
        text_lower = text.lower()
        for pattern in self.error_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    def _extract_evidence(self, text: str) -> str:
        for pattern in self.error_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)[:200]
        return "SQL error pattern detected"
