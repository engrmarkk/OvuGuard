import requests
import json
from environmentals import METASPLOIT_BASE_URL, METASPLOIT_PASSWORD, METASPLOIT_USERNAME
from logger import logger


class MetasploitBase:
    def __init__(self):
        self.base_url = METASPLOIT_BASE_URL
        self.password = METASPLOIT_PASSWORD
        self.username = METASPLOIT_USERNAME
        self.token = self.authenticate()

    async def authenticate(self):
        """Authenticate with Metasploit RPC API"""
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"username": self.username, "password": self.password},
            headers={"Content-Type": "application/json"},
        )
        resp = response.json()
        logger.info(f"RESPONSE FROM METASPLOIT AUTH: {resp}")
        return resp.get("token")
