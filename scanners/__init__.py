from abc import ABC, abstractmethod
from typing import List, Dict, Any
from utils.http_client import HTTPClient


class BaseDetector(ABC):
    def __init__(self, http_client: HTTPClient, endpoints: List[Dict]):
        self.http_client = http_client
        self.endpoints = endpoints

    @abstractmethod
    async def detect(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        pass

    def _calculate_severity(self, confidence: float, impact: str) -> str:
        if confidence > 0.8 and impact == "high":
            return "critical"
        elif confidence > 0.6:
            return "high"
        elif confidence > 0.4:
            return "medium"
        else:
            return "low"
