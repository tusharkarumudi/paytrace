"""Collectors. Importing this package registers all built-ins."""
from . import (  # noqa: F401
    analytics,
    artifacts,
    base,
    business,
    disclosure,
    infra,
    lookups,
    persona,
    records,
    registries,
    surface,
)
from .base import Collector, build_all, register, registry  # noqa: F401

#: Names the engine treats as person-scoped.
PERSONA_COLLECTOR_NAMES = frozenset({
    "gravatar", "github_intel", "username_expand", "holehe", "pgp_wkd",
})

try:  # pragma: no cover
    from attribution_graph import PERSON_SCOPED_COLLECTORS
    PERSON_SCOPED_COLLECTORS.update(PERSONA_COLLECTOR_NAMES)
except ImportError:  # pragma: no cover
    pass
