"""Collector base class and registry for paytrace.

Collectors satisfy the ``attribution_graph.Collector`` protocol. Each declares a
``source_class`` that is checked against the deny list when the engine is
constructed -- a collector declaring a denied class raises at load, not at call.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from attribution_graph import CaseScope, Claim, Identifier, IdKind, SourceClass

from ..net import Fetcher


class Collector:
    name: str = "base"
    source_class: SourceClass = SourceClass.PUBLIC_PROTOCOL
    accepts: Sequence[IdKind] = ()
    needs_key: str | None = None
    priority: int = 3

    def __init__(self, fetcher: Fetcher, scope: CaseScope) -> None:
        self.fetcher = fetcher
        self.scope = scope

    async def collect(self, ident: Identifier) -> Iterable[Claim]:
        raise NotImplementedError

    def claim(self, subject: Identifier, predicate, obj, source_url: str, **kw) -> Claim:
        return Claim(
            subject=subject, predicate=predicate, object=obj,
            collector=self.name, source_url=source_url, **kw,
        )


_REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Collector]]:
    return dict(_REGISTRY)


def build_all(
    fetcher: Fetcher, scope: CaseScope, enabled: set[str] | None = None
) -> list[Collector]:
    out: list[Collector] = []
    for name, cls in _REGISTRY.items():
        if enabled is not None and name not in enabled:
            continue
        scope.check_source_class(name, cls.source_class)
        out.append(cls(fetcher, scope))
    out.sort(key=lambda c: c.priority)
    return out
