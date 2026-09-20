"""Collector contract tests: registration, source classes, deny-list behaviour."""

import pytest
from attribution_graph import CaseScope, IdKind, PolicyError, SourceClass

from paytrace.collectors import registry
from paytrace.collectors.base import Collector, build_all, register


@pytest.fixture
def scope(tmp_path):
    p = tmp_path / "case.yaml"
    p.write_text(
        "case_ref: T-1\nauthorization: test\nseeds: [domain:example.com]\n"
        f"audit_path: {tmp_path / 'audit.jsonl'}\n"
    )
    return CaseScope.load(str(p))


def test_expected_collectors_registered():
    names = set(registry())
    for expected in ("ads_txt_owner", "sellers_json", "gleif", "sec_edgar",
                     "imprint", "rdap", "crtsh"):
        assert expected in names


def test_no_collector_declares_a_denied_source_class():
    from attribution_graph import DENIED_SOURCE_CLASSES
    for name, cls in registry().items():
        assert cls.source_class not in DENIED_SOURCE_CLASSES, name


def test_every_collector_declares_accepted_kinds():
    for name, cls in registry().items():
        if name == "base":
            continue
        assert cls.accepts, f"{name} accepts nothing"
        assert all(isinstance(k, IdKind) for k in cls.accepts)


def test_denied_collector_raises_at_load_not_at_call(scope):
    @register
    class Broker(Collector):
        name = "test_people_search"
        source_class = SourceClass.DATA_BROKER
        accepts = (IdKind.PERSON_NAME,)

    with pytest.raises(PolicyError, match="denied source class"):
        build_all(None, scope)
    registry().pop("test_people_search", None)
    from paytrace.collectors.base import _REGISTRY
    _REGISTRY.pop("test_people_search", None)
