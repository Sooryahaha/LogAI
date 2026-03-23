"""
AI Client — async HTTP client for Ollama local LLM.
Provides graceful fallback if Ollama is unavailable.
"""

import httpx

from app.core.config import settings
from app.core.logging_config import logger


class AIClient:
    """
    Async client for Ollama local LLM inference.
    Used only for insight generation — detection is always deterministic.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT

    async def generate(self, prompt: str) -> str | None:
        """
        Send a prompt to Ollama and return the generated text.
        Returns None if Ollama is unavailable.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 256,
                        },
                    },
                )
                response.raise_for_status()
                data = response.json()
                result = data.get("response", "").strip()
                logger.info(f"Ollama response received ({len(result)} chars)")
                return result
        except httpx.ConnectError:
            logger.warning("Ollama not available — using rule-based fallback")
            return None
        except httpx.TimeoutException:
            logger.warning("Ollama request timed out — using rule-based fallback")
            return None
        except Exception as e:
            logger.error(f"Ollama error: {e} — using rule-based fallback")
            return None

    async def is_available(self) -> bool:
        """Check if Ollama is running and accessible."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False
