from openai import OpenAI, OpenAIError
import os
from app.config import settings


def oxy_connection():
    try:
        api_key = settings.OXYY_API_KEY.get_secret_value()

        if not api_key:
            raise ValueError("OXYY_API_KEY is missing from environment variables")

        client = OpenAI(
            api_key=api_key,
            base_url="https://api.oxyy.ai/v1"
        )

        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[
                {"role": "user", "content": "Say OK"}
            ],
            max_tokens=1,
            temperature=0
        )

        print("Response:", response.choices[0].message.content)
        print("Usage:", response.usage)

        return True

    except OpenAIError as e:
        print("OpenAI/Oxyy API error:", e)
        return False

    except ValueError as e:
        print("Configuration error:", e)
        return False

    except Exception as e:
        print("Unexpected error:", e)
        return False