"""Land-record collectors must remain entity-keyed."""

import pytest
from attribution_graph import Identifier, IdKind

from paytrace.collectors.records import (
    LandRecordCollector,
    PersonKeyedQueryRefused,
    is_entity_name,
)


class Dummy(LandRecordCollector):
    name = "dummy_land"

    def __init__(self):
        pass

    async def collect_for_entity(self, ident):
        return []


@pytest.mark.parametrize("name", [
    "ACME HOLDINGS LLC", "Example Properties Ltd", "Blackstone Realty Corp",
    "Muster GmbH", "Foo Ventures LP", "The Smith Family Trust",
])
def test_entity_names_recognized(name):
    assert is_entity_name(name)


@pytest.mark.parametrize("name", [
    "JANE Q OPERATOR", "Smith, John A", "Maria Gonzalez", "Wei Chen",
])
def test_person_names_not_treated_as_entities(name):
    """Conservative by design: an unmatched name is a person and is suppressed.
    A false negative costs a lead; a false positive publishes a home address."""
    assert not is_entity_name(name)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,value", [
    (IdKind.PERSON_NAME, "Jane Q Operator"),
    (IdKind.EMAIL, "jane@example.com"),
    (IdKind.HANDLE, "github:jane"),
])
async def test_person_keyed_query_is_refused(kind, value):
    with pytest.raises(PersonKeyedQueryRefused):
        await Dummy().collect(Identifier(kind, value))


@pytest.mark.asyncio
async def test_entity_keyed_query_is_allowed():
    assert await Dummy().collect(Identifier(IdKind.ORG_NAME, "Acme Holdings LLC")) == []


def test_person_owned_parcel_yields_marker_not_identity():
    c = Dummy().owner_claims(
        Identifier(IdKind.URL, "acris:123"), "JANE Q OPERATOR",
        "https://example", "g",
    )
    assert len(c) == 1
    assert c[0].object == "chain_terminates_natural_person"
    assert "suppressed" in c[0].raw
    # the name must not survive anywhere in the emitted claim
    assert "JANE" not in repr(c[0].to_dict()).upper()


def test_entity_owned_parcel_yields_real_ownership_edge():
    c = Dummy().owner_claims(
        Identifier(IdKind.URL, "acris:123"), "ACME HOLDINGS LLC",
        "https://example", "g",
    )
    assert c[0].subject.value == "ACME HOLDINGS LLC"
    assert c[0].object.value == "acris:123"


def test_land_collectors_never_accept_person_names():
    from paytrace.collectors import registry
    for name, cls in registry().items():
        if issubclass(cls, LandRecordCollector):
            assert IdKind.PERSON_NAME not in cls.accepts, name
