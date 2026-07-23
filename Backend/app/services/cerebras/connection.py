"""
Cerebras API connection and testing service.
Handles connection setup and health checks for Cerebras AI services.
"""
from app.config import settings
import requests


def test_cerebras_connection():
    """
    Test the Cerebras API connection.
"""
    api_key = settings.CEREBRAS_API_KEY.get_secret_value()
    url = "https://api.cerebras.ai/v1/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    try:
       test_cerebras_connection()
    except Exception as e:
         print(f"Cerebras connection test failed: {e}")
