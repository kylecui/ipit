"""
LLM client for narrative report generation.

Uses OpenAI-compatible API. Supports any provider that implements
the OpenAI chat completions interface (OpenAI, Azure, Ollama, etc.).

If LLM_API_KEY is not configured, the client is disabled and all
generate() calls return None (triggering template-only fallback).

Per-user overrides: generate() accepts optional api_key/model/base_url
so each user's admin-portal settings take effect at request time.
"""

import logging
from typing import Any, Dict, Optional

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

    def is_enabled(self, overrides: Optional[Dict[str, Any]] = None) -> bool:
        """Check if LLM is available, considering optional per-user overrides."""
        if overrides and overrides.get("api_key"):
            return True
        return self.enabled

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
        *,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate text using LLM API.

        Args:
            system_prompt: System role instructions
            user_prompt: User message with data and instructions
            temperature: Sampling temperature (lower = more deterministic)
            max_tokens: Maximum tokens in response
            api_key: Per-request override (from user's admin settings)
            model: Per-request override
            base_url: Per-request override

        Returns:
            Generated text, or None if LLM is unavailable/failed
        """
        effective_key = api_key or self.api_key
        effective_model = model or self.model
        effective_base = (base_url or self.base_url).rstrip("/")

        if not effective_key:
            logger.debug("LLM not configured, skipping generation")
            return None

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{effective_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {effective_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": effective_model,
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
                    "LLM generation completed (%d tokens, model=%s)",
                    data.get("usage", {}).get("total_tokens", 0),
                    effective_model,
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

    async def validate_connection(
        self,
        api_key: str,
        base_url: str,
    ) -> Dict[str, Any]:
        """Test an API key + base_url by listing available models.

        Returns:
            {"ok": bool, "models": list[str], "error": str | None}
        """
        effective_base = base_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{effective_base}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                response.raise_for_status()
                data = response.json()
                models = sorted([m["id"] for m in data.get("data", []) if m.get("id")])
                return {"ok": True, "models": models, "error": None}
        except httpx.TimeoutException:
            return {"ok": False, "models": [], "error": "Connection timed out"}
        except httpx.HTTPStatusError as e:
            return {
                "ok": False,
                "models": [],
                "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}",
            }
        except Exception as e:
            return {"ok": False, "models": [], "error": str(e)}


# Global instance
llm_client = LLMClient()
