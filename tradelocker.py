import requests
import json
import logging

logger = logging.getLogger(__name__)


class TradeLocker:
    def __init__(self, env="demo"):
        self.env = env
        self.base_url = f"https://{env}.tradelocker.com/backend-api"
        self.token = None
        logger.debug(f"TradeLocker initialized with environment: {env}")

    def get_jwt_token(self, email, password, server):
        """
        Get JWT token from TradeLocker API
        """
        url = f"{self.base_url}/auth/jwt/token"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        payload = {
            "email": email,
            "password": password,
            "server": server
        }

        logger.debug(f"Making API request to {url}")

        try:
            response = requests.post(url, headers=headers, json=payload)

            logger.debug(f"API response status code: {response.status_code}")

            # Accept both 200 and 201 as success codes
            if response.status_code not in [200, 201]:
                logger.error(f"API Error: {response.status_code} - {response.text}")
                raise Exception(f"API Error: {response.status_code} - {response.text}")

            result = response.json()
            logger.debug("Successfully obtained JWT token")
            # Use accessToken instead of token based on the response structure
            self.token = result.get("accessToken")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            raise Exception(f"Connection error: {str(e)}")

    def get_all_accounts(self):
        """
        Get all accounts from TradeLocker API
        """
        if not self.token:
            logger.error("JWT token is required. Call get_jwt_token first.")
            raise Exception("JWT token is required. Call get_jwt_token first.")

        url = f"{self.base_url}/auth/jwt/all-accounts"
        headers = {
            "Authorization": f"Bearer {self.token}"
        }

        params = {
            "env": self.env
        }

        logger.debug(f"Making API request to {url}")

        try:
            response = requests.get(url, headers=headers, params=params)

            logger.debug(f"API response status code: {response.status_code}")
            logger.debug(f"API response body: {response.text}")

            if response.status_code not in [200, 201]:
                logger.error(f"API Error: {response.status_code} - {response.text}")
                raise Exception(f"API Error: {response.status_code} - {response.text}")

            result = response.json()
            logger.debug(f"Successfully retrieved accounts data")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            raise Exception(f"Connection error: {str(e)}")
