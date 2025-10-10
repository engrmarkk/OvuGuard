import httpx
import asyncio
import logging
from typing import Dict, Any, Optional
from environmentals import SCANNER_TIMEOUT, SCANNER_USER_AGENT, SCANNER_MAX_RETRIES
from logger import logger


# class HTTPClient:
#     def __init__(self):
#         self.timeout = httpx.Timeout(SCANNER_TIMEOUT)
#         self.headers = {"User-Agent": SCANNER_USER_AGENT}

#     async def send_request(
#         self,
#         method: str,
#         url: str,
#         params: Optional[Dict] = None,
#         headers: Optional[Dict] = None,
#         data: Optional[Any] = None,
#         json: Optional[Dict] = None,
#     ) -> httpx.Response:

#         last_exception = None

#         for attempt in range(SCANNER_MAX_RETRIES):
#             try:
#                 async with httpx.AsyncClient(
#                     timeout=self.timeout,
#                     headers={**self.headers, **(headers or {})},
#                     follow_redirects=True,
#                     verify=False,
#                 ) as client:

#                     response = await client.request(
#                         method=method.upper(),
#                         url=url,
#                         params=params,
#                         headers=headers,
#                         data=data,
#                         json=json,
#                     )

#                     logger.debug(
#                         f"HTTP {method} {url} - Status: {response.status_code}"
#                     )
#                     return response

#             except Exception as e:
#                 last_exception = e
#                 logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")

#                 if attempt < SCANNER_MAX_RETRIES - 1:
#                     await asyncio.sleep(1 * (attempt + 1))

#         raise last_exception or Exception("All retry attempts failed")


class HTTPClient:
    def __init__(self):
        self.timeout = httpx.Timeout(SCANNER_TIMEOUT)
        self.headers = {
            "User-Agent": SCANNER_USER_AGENT,
            "Accept": "application/json, text/html, */*",
        }

    async def send_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
    ) -> httpx.Response:

        last_exception = None

        for attempt in range(SCANNER_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    headers={**self.headers, **(headers or {})},
                    follow_redirects=True,
                    verify=True,  # Changed to True for HTTPS validation
                ) as client:

                    # Log the attempt
                    logger.info(f"Attempt {attempt + 1} for {method} {url}")

                    response = await client.request(
                        method=method.upper(),
                        url=url,
                        params=params,
                        headers=headers,
                        data=data,
                        json=json,
                    )

                    logger.info(f"HTTP {method} {url} - Status: {response.status_code}")
                    return response

            except httpx.ConnectError as e:
                last_exception = e
                logger.warning(
                    f"Connection error on attempt {attempt + 1} for {url}: {e}"
                )
            except httpx.TimeoutException as e:
                last_exception = e
                logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
            except httpx.HTTPError as e:
                last_exception = e
                logger.warning(f"HTTP error on attempt {attempt + 1} for {url}: {e}")
            except Exception as e:
                last_exception = e
                logger.error(
                    f"Unexpected error on attempt {attempt + 1} for {url}: {e}"
                )

            if attempt < SCANNER_MAX_RETRIES - 1:
                wait_time = 2 * (attempt + 1)  # Exponential backoff: 2, 4, 6 seconds
                logger.info(f"Waiting {wait_time}s before retry...")
                await asyncio.sleep(wait_time)

        # Log the final failure
        error_msg = f"All {SCANNER_MAX_RETRIES} attempts failed for {url}"
        if last_exception:
            error_msg += f": {last_exception}"
        logger.error(error_msg)

        raise last_exception or Exception(error_msg)

    async def test_connection(self, url: str) -> Dict[str, Any]:
        """Test if we can connect to the target URL"""
        try:
            response = await self.send_request("GET", url)
            return {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "can_connect": True,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "can_connect": False}
