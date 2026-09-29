from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import quote

import httpx

from anomaly_detection.config import Settings


class ProviderError(RuntimeError):
    pass


class AIProvider(ABC):
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client

    @abstractmethod
    async def complete(self, system: str, user: str) -> str:
        raise NotImplementedError

    async def _post(self, url: str, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self.client.post(url, headers=headers, json=body)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:500]
            raise ProviderError(f"AI API HTTP {exc.response.status_code}: {detail}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            # Exception text can include a URL containing a provider key (Gemini).
            raise ProviderError(f"AI API request failed: {type(exc).__name__}") from exc


class OpenAICompatibleProvider(AIProvider):
    async def complete(self, system: str, user: str) -> str:
        base = self.settings.ai_base_url.rstrip("/") or "https://api.openai.com/v1"
        data = await self._post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {self.settings.ai_api_key}"},
            body={
                "model": self.settings.ai_model,
                "temperature": self.settings.ai_temperature,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return data["choices"][0]["message"]["content"]


class AzureOpenAIProvider(AIProvider):
    async def complete(self, system: str, user: str) -> str:
        if not self.settings.ai_base_url:
            raise ProviderError("AI_BASE_URL must be the Azure OpenAI resource endpoint")
        deployment = quote(self.settings.ai_model, safe="")
        url = (
            f"{self.settings.ai_base_url.rstrip('/')}/openai/deployments/{deployment}/chat/completions"
            f"?api-version={quote(self.settings.ai_api_version, safe='')}"
        )
        data = await self._post(
            url,
            headers={"api-key": self.settings.ai_api_key},
            body={
                "temperature": self.settings.ai_temperature,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return data["choices"][0]["message"]["content"]


class AnthropicProvider(AIProvider):
    async def complete(self, system: str, user: str) -> str:
        base = self.settings.ai_base_url.rstrip("/") or "https://api.anthropic.com"
        data = await self._post(
            f"{base}/v1/messages",
            headers={
                "x-api-key": self.settings.ai_api_key,
                "anthropic-version": "2023-06-01",
            },
            body={
                "model": self.settings.ai_model,
                "max_tokens": 3000,
                "temperature": self.settings.ai_temperature,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        return "".join(part.get("text", "") for part in data.get("content", []))


class GeminiProvider(AIProvider):
    async def complete(self, system: str, user: str) -> str:
        base = self.settings.ai_base_url.rstrip("/") or "https://generativelanguage.googleapis.com"
        model = quote(self.settings.ai_model, safe="")
        data = await self._post(
            f"{base}/v1beta/models/{model}:generateContent?key={quote(self.settings.ai_api_key, safe='')}",
            headers={"Content-Type": "application/json"},
            body={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {
                    "temperature": self.settings.ai_temperature,
                    "responseMimeType": "application/json",
                },
            },
        )
        return data["candidates"][0]["content"]["parts"][0]["text"]


class OllamaProvider(AIProvider):
    async def complete(self, system: str, user: str) -> str:
        base = self.settings.ai_base_url.rstrip("/") or "http://localhost:11434"
        data = await self._post(
            f"{base}/api/chat",
            headers={"Content-Type": "application/json"},
            body={
                "model": self.settings.ai_model,
                "stream": False,
                "format": "json",
                "options": {"temperature": self.settings.ai_temperature},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return data["message"]["content"]


PROVIDERS: dict[str, type[AIProvider]] = {
    "openai": OpenAICompatibleProvider,
    "openai_compatible": OpenAICompatibleProvider,
    "azure_openai": AzureOpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def make_provider(settings: Settings, client: httpx.AsyncClient) -> AIProvider:
    provider = settings.ai_provider.strip().lower()
    if provider not in PROVIDERS:
        raise ProviderError(
            f"Unsupported AI_PROVIDER '{settings.ai_provider}'. "
            f"Choose one of: {', '.join(sorted(PROVIDERS))}"
        )
    if provider != "ollama" and not settings.ai_api_key:
        raise ProviderError("AI_API_KEY is not configured")
    if not settings.ai_model:
        raise ProviderError("AI_MODEL is not configured")
    return PROVIDERS[provider](settings, client)


def parse_json_object(text: str) -> dict[str, Any]:
    clean = text.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1]
        clean = clean.rsplit("```", 1)[0]
    try:
        value = json.loads(clean)
    except json.JSONDecodeError as exc:
        start, end = clean.find("{"), clean.rfind("}")
        if start < 0 or end <= start:
            raise ProviderError("AI response was not a JSON object") from exc
        try:
            value = json.loads(clean[start : end + 1])
        except json.JSONDecodeError as nested:
            raise ProviderError("AI response contained invalid JSON") from nested
    if not isinstance(value, dict):
        raise ProviderError("AI response must be a JSON object")
    return value
