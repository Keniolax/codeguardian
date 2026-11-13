"""Model backends behind one small interface: complete_json(system, user, schema)."""

import json
import os
import urllib.request

DEFAULT_MODEL = "claude-sonnet-5-5"


class ModelRefused(RuntimeError):
    pass


class AnthropicProvider:
    """Claude API. Uses structured outputs, so the reply is JSON in the given schema.

    Server-side fallback is on: if a safety classifier declines the request, the API
    reruns it on a fallback model in the same call, and the report names the model that
    actually answered.
    """

    name = "anthropic"

    def __init__(self, model=None, client=None, effort="medium"):
        self.model = model or os.environ.get("CODEGUARDIAN_MODEL", DEFAULT_MODEL)
        self.effort = effort
        if client is None:
            import anthropic

            client = anthropic.Anthropic(max_retries=3)
        self.client = client

    def complete_json(self, system, user, schema):
        response = self.client.beta.messages.create(
            model=self.model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            raise ModelRefused(f"model refused: {getattr(details, 'category', None)}")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("model output hit max_tokens")
        text = next(b.text for b in response.content if b.type == "text")
        usage = {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens}
        return json.loads(text), {"model": self.model, "served_by": response.model, "usage": usage}


class OllamaProvider:
    """A local model through Ollama's chat API, for runs without the Claude API."""

    name = "ollama"

    def __init__(self, model=None, host=None):
        self.model = model or os.environ.get("CODEGUARDIAN_OLLAMA_MODEL", "qwen3:8b")
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")

    def complete_json(self, system, user, schema):
        body = json.dumps({
            "model": self.model,
            "stream": False,
            "format": schema,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.load(resp)
        usage = {"input_tokens": data.get("prompt_eval_count", 0), "output_tokens": data.get("eval_count", 0)}
        return json.loads(data["message"]["content"]), {"model": self.model, "served_by": self.model, "usage": usage}


def get_provider(name):
    if name == "anthropic":
        return AnthropicProvider()
    if name == "ollama":
        return OllamaProvider()
    raise ValueError(f"unknown provider {name!r}")
