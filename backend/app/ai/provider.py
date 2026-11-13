"""AI provider adapters. Optional: with provider ``none`` the app runs fully on deterministic logic.

Only *structured findings metadata* is ever sent - never PCAP bytes, payloads, credentials or IP addresses.
In local-only mode (default) only loopback endpoints are permitted.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class AiError(RuntimeError):
    pass


def check_endpoint(endpoint: str, local_only: bool) -> None:
    host = urlparse(endpoint).hostname or ""
    if urlparse(endpoint).scheme not in ("http", "https"):
        raise AiError("AI endpoint must be an http(s) URL")
    if local_only and host not in LOOPBACK:
        raise AiError(f"Local-only privacy mode is on: refusing to contact non-loopback host '{host}'. Disable it in Settings to use a remote provider.")


class Provider:
    name = "none"
    model = ""

    def complete(self, prompt: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, endpoint: str, model: str, client: httpx.Client | None = None):
        self.endpoint, self.model, self._client = endpoint.rstrip("/"), model, client

    def complete(self, prompt: str) -> str:
        c = self._client or httpx.Client(timeout=90)
        try:
            r = c.post(f"{self.endpoint}/api/generate", json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"})
            r.raise_for_status()
            return r.json().get("response", "")
        except (httpx.HTTPError, ValueError) as exc:
            raise AiError(f"Ollama request failed: {exc}") from exc


class OpenAICompatProvider(Provider):
    name = "openai_compatible"

    def __init__(self, endpoint: str, model: str, api_key: str | None, client: httpx.Client | None = None):
        self.endpoint, self.model, self.api_key, self._client = endpoint.rstrip("/"), model, api_key, client

    def complete(self, prompt: str) -> str:
        c = self._client or httpx.Client(timeout=90)
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            r = c.post(f"{self.endpoint}/v1/chat/completions", headers=headers,
                       json={"model": self.model, "messages": [{"role": "user", "content": prompt}], "response_format": {"type": "json_object"}})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise AiError(f"OpenAI-compatible request failed: {exc}") from exc


def build_provider(cfg: dict, api_key: str | None = None) -> Provider | None:
    kind = cfg.get("ai_provider", "none")
    if kind == "none":
        return None
    check_endpoint(cfg["ai_endpoint"], bool(cfg.get("local_only_mode", True)))
    if kind == "ollama":
        return OllamaProvider(cfg["ai_endpoint"], cfg["ai_model"])
    if kind == "openai_compatible":
        return OpenAICompatProvider(cfg["ai_endpoint"], cfg["ai_model"], api_key)
    raise AiError(f"unknown provider {kind}")
