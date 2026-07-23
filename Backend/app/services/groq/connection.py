"""
Groq API connection and testing service.
Handles connection setup and health checks for Groq AI services.
"""
import os
from langchain_groq import ChatGroq
from app.config import settings
import requests


def test_groq_connection():
    """
    Test the Groq API connection.
""" 
    api_key = settings.GROQ_API_KEY.get_secret_value()
    url = "https://api.groq.com/openai/v1/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    try:
       test_groq_connection()
    except Exception as e:
         print(f"Groq connection test failed: {e}")
    