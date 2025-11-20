import os
from typing import List
import httpx
from .prompts import build_messages_for_snippet
from .postprocessing import parse_ai_response
from ..core.models import CodeSnippetContext, Finding
from ..core.config import Config


class OpenAIError(Exception):
    pass


def analyze_snippet_with_ai(snippet: CodeSnippetContext, config: Config) -> List[Finding]:
    ai_enabled = config.get("ai", "enabled", default=True)
    if not ai_enabled:
        return []

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        # Sin API key, no usamos IA
        return []

    model = config.get("ai", "model", default="gpt-4.1-mini")
    base_url = config.get("ai", "base_url", default="https://api.openai.com/v1/chat/completions")
    temperature = float(config.get("ai", "temperature", default=0.0))
    min_conf = float(config.get("severity_thresholds", "ai_min_confidence", default=0.5))

    payload_base = build_messages_for_snippet(snippet)
    payload = {
        "model": model,
        "messages": payload_base["messages"],
        "temperature": temperature,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        resp = httpx.post(base_url, json=payload, headers=headers, timeout=60.0)
    except httpx.HTTPError as e:
        raise OpenAIError(f"HTTP error calling OpenAI API: {e}") from e

    if resp.status_code != 200:
        raise OpenAIError(f"OpenAI API returned status {resp.status_code}: {resp.text}")

    data = resp.json()
    # Para /v1/chat/completions
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        raise OpenAIError("Unexpected response structure from OpenAI API")

    return parse_ai_response(snippet, content, min_confidence=min_conf)
