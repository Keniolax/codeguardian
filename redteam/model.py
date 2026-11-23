"""Model access for the harness: a seeded Ollama client and a request trace."""

import hashlib
import json
import os
import urllib.request


# Ollama cuts a prompt longer than the context window from the front, which would drop
# the system prompt. 8192 tokens holds the longest payload with room to spare.
NUM_CTX = 8192


class SeededOllama:
    """Ollama chat with a fixed temperature and seed, so a run can be replayed."""

    name = "ollama"

    def __init__(self, model, temperature, seed, host=None):
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")

    def complete_json(self, system, user, schema):
        body = json.dumps({
            "model": self.model,
            "stream": False,
            "format": schema,
            "options": {"temperature": self.temperature, "seed": self.seed, "num_ctx": NUM_CTX},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=900) as resp:
            data = json.load(resp)
        usage = {"input_tokens": data.get("prompt_eval_count", 0), "output_tokens": data.get("eval_count", 0)}
        return json.loads(data["message"]["content"]), {"model": self.model, "served_by": self.model,
                                                        "usage": usage}


class Trace:
    """Wrap a provider and keep every request and reply for the evidence file."""

    def __init__(self, provider):
        self.provider = provider
        self.name = getattr(provider, "name", "trace")
        self.calls = []

    def complete_json(self, system, user, schema):
        record = {
            "system_sha256": hashlib.sha256(system.encode()).hexdigest(),
            "user_sha256": hashlib.sha256(user.encode()).hexdigest(),
            "schema_keys": sorted(schema.get("properties", {})),
            "system": system,
            "user": user,
        }
        self.calls.append(record)
        try:
            raw, meta = self.provider.complete_json(system, user, schema)
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            raise
        record["reply"] = raw
        return raw, meta
