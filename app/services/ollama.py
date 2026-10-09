"""Ollama REST API client service for local LLM inference."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel, ValidationError

from app.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class OllamaError(Exception):
    """Base exception for Ollama interactions."""
    pass


class OllamaUnavailableError(OllamaError):
    """Raised when Ollama local daemon is not running or unreachable."""
    pass


class OllamaMalformedResponseError(OllamaError):
    """Raised when Ollama returns an invalid or unparseable structured response."""
    pass


class OllamaService:
    """Client for local Ollama HTTP REST API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout_seconds = timeout_seconds or settings.ollama_timeout_seconds

    def check_health(self) -> Dict[str, Any]:
        """Check whether local Ollama server is running and reachable."""
        endpoint = f"{self.base_url}/api/version"
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "available": True,
                        "version": data.get("version", "unknown"),
                        "base_url": self.base_url,
                    }
                return {
                    "available": False,
                    "error": f"Ollama returned unexpected status HTTP {resp.status_code}",
                    "base_url": self.base_url,
                }
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            return {
                "available": False,
                "error": (
                    f"Ollama server is unreachable at {self.base_url}. "
                    "Ensure Ollama is started (run 'ollama serve' or open the Ollama app)."
                ),
                "base_url": self.base_url,
                "details": str(exc),
            }
        except Exception as exc:
            return {
                "available": False,
                "error": f"Health check failed: {exc}",
                "base_url": self.base_url,
            }

    def list_installed_models(self) -> List[str]:
        """Retrieve list of locally pulled/installed model tags."""
        endpoint = f"{self.base_url}/api/tags"
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(endpoint)
                resp.raise_for_status()
                data = resp.json()
                models = data.get("models", [])
                return [m.get("name", "") for m in models if "name" in m]
        except Exception as exc:
            logger.warning("Could not list Ollama models: %s", exc)
            return []

    def _clean_json_text(self, text: str) -> str:
        """Strip markdown fences and formatting artifacts from LLM JSON output."""
        cleaned = text.strip()
        # Remove markdown code blocks if wrapped: ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        return cleaned

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        json_format: bool = False,
        temperature: float = 0.1,
    ) -> str:
        """Send prompt to Ollama generate endpoint and return raw text response.

        Args:
            prompt: User/task prompt text.
            system: Optional system instruction prompt.
            json_format: Whether to enforce JSON mode in Ollama.
            temperature: Sampling temperature (low by default for deterministic reviews).

        Returns:
            Generated response string.

        Raises:
            OllamaUnavailableError: If Ollama daemon is unreachable.
            OllamaError: If generation request fails.
        """
        endpoint = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if system:
            payload["system"] = system
        if json_format:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(endpoint, json=payload)
                response.raise_for_status()
                result = response.json()
                return result.get("response", "")
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise OllamaUnavailableError(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Please verify Ollama is running on your machine ('ollama serve')."
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaError(
                f"Ollama request timed out after {self.timeout_seconds} seconds for model '{self.model}'."
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaError(
                f"Ollama returned HTTP error {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except Exception as exc:
            raise OllamaError(f"Unexpected error communicating with Ollama: {exc}") from exc

    def generate_structured(
        self,
        prompt: str,
        schema_class: Type[T],
        system: Optional[str] = None,
        temperature: float = 0.1,
    ) -> T:
        """Generate structured LLM output validated against a Pydantic schema class.

        Args:
            prompt: Task prompt describing the required reasoning and data.
            schema_class: Target Pydantic model class to validate and instantiate.
            system: System instructions for role, constraints, and tone.
            temperature: Sampling temperature.

        Returns:
            Instantiated and validated Pydantic model instance.

        Raises:
            OllamaUnavailableError: If Ollama is unreachable.
            OllamaMalformedResponseError: If model output does not match schema.
        """
        raw_text = self.generate(
            prompt=prompt,
            system=system,
            json_format=True,
            temperature=temperature,
        )

        cleaned_json = self._clean_json_text(raw_text)

        try:
            parsed = json.loads(cleaned_json)
        except json.JSONDecodeError as exc:
            raise OllamaMalformedResponseError(
                f"LLM returned invalid JSON syntax: {exc}. Response text: {raw_text[:300]}"
            ) from exc

        try:
            return schema_class.model_validate(parsed)
        except ValidationError as exc:
            raise OllamaMalformedResponseError(
                f"LLM JSON response does not conform to schema {schema_class.__name__}: {exc}. "
                f"Parsed dictionary was: {parsed}"
            ) from exc
