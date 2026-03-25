"""
AI Client — Google Gemini API client for cybersecurity log analysis.
Provides graceful fallback if Gemini is unavailable or API key not set.
"""

from google import genai
from google.genai import types

from app.core.config import settings
from app.core.logging_config import logger


class AIClient:
    """
    Async-compatible client for Google Gemini LLM inference.
    Used only for insight generation — detection is always deterministic.
    """

    def __init__(self):
        self.model_name = settings.GEMINI_MODEL
        self.api_key = settings.GEMINI_API_KEY
        self.client = None

        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                logger.info(f"Gemini AI client initialized (model={self.model_name})")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini Client: {e}")
                self.client = None
        else:
            logger.warning("GEMINI_API_KEY not set — AI insights disabled, using rule-based fallback")

    async def generate(self, prompt: str) -> str | None:
        """
        Send a prompt to Gemini and return the generated text.
        Returns None if Gemini is unavailable.
        """
        if not self.client:
            return None

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=1024,
                ),
            )

            if response and response.text:
                result = response.text.strip()
                logger.info(f"Gemini response received ({len(result)} chars)")
                return result

            logger.warning("Gemini returned empty response")
            return None

        except Exception as e:
            logger.error(f"Gemini error: {e} — using rule-based fallback")
            return None

    async def is_available(self) -> bool:
        """Check if Gemini is configured and accessible."""
        return self.client is not None
