"""
LLM client for narrative report generation.

Uses OpenAI-compatible API. Supports any provider that implements
the OpenAI chat completions interface (OpenAI, Azure, Ollama, etc.).

If LLM_API_KEY is not configured, the client is disabled and all
generate() calls return None (triggering template-only fallback).
"""

import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class LLMClient:
    """Async LLM client for generating narrative analysis paragraphs."""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.model = settings.llm_model
        self.base_url = settings.llm_base_url.rstrip("/")

    @property
    def enabled(self) -> bool:
        """Check if LLM is configured and available."""
        return bool(self.api_key)

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> Optional[str]:
        """
        Generate text using LLM API.

        Args:
            system_prompt: System role instructions
            user_prompt: User message with data and instructions
            temperature: Sampling temperature (lower = more deterministic)
            max_tokens: Maximum tokens in response

        Returns:
            Generated text, or None if LLM is unavailable/failed
        """
        if not self.enabled:
            logger.debug("LLM not configured, skipping generation")
            return None

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    },
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                logger.info(
                    "LLM generation completed (%d tokens)",
                    data.get("usage", {}).get("total_tokens", 0),
                )
                return content

        except httpx.TimeoutException:
            logger.warning("LLM request timed out")
            return None
        except httpx.HTTPStatusError as e:
            logger.warning(
                "LLM API error: %s %s", e.response.status_code, e.response.text[:200]
            )
            return None
        except Exception as e:
            logger.warning("LLM generation failed: %s", e)
            return None


# Global instance
llm_client = LLMClient()
