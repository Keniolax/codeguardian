"""Collectors read exported files in the formats the real tools write.

A collector that cannot read its input raises CollectorError before it writes anything.
The caller records the source as failed, which makes all its facts stale. A bad file must
never look like an empty, clean environment.
"""

import json
from pathlib import Path


class CollectorError(RuntimeError):
    pass


class Delta:
    """What a model change touched, so the pipeline re-runs only the rules that can see it."""

    def __init__(self):
        self.entities = {}  # id -> type
        self.edge_types = set()

    def entity(self, eid, etype):
        self.entities[eid] = etype

    def edge(self, etype):
        self.edge_types.add(etype)

    def merge(self, other):
        self.entities.update(other.entities)
        self.edge_types |= other.edge_types
        return self

    @property
    def entity_types(self):
        return set(self.entities.values())

    def __bool__(self):
        return bool(self.entities or self.edge_types)


def read_json(path, what):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CollectorError(f"{what}: cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"{what}: {path} is not JSON: {exc}") from exc


def need(cond, what, message):
    if not cond:
        raise CollectorError(f"{what}: {message}")
