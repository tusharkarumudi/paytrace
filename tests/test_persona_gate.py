"""Persona collectors are opt-in behind two keys, and enumeration behind three."""

import pytest
from attribution_graph import CaseScope

from paytrace.collectors import PERSONA_COLLECTOR_NAMES, registry


def _scope(tmp_path, **extra):
    lines = ["case_ref: T", "authorization: test", "seeds: [domain:a.example]",
             f"audit_path: {tmp_path / 'a.jsonl'}"]
    for k, v in extra.items():
        lines.append(f"{k}: {v}")
    p = tmp_path / "c.yaml"
    p.write_text("\n".join(lines) + "\n")
    return CaseScope.load(str(p))


def test_persona_collectors_are_registered_but_not_enabled(tmp_path):
    reg = registry()
    for n in PERSONA_COLLECTOR_NAMES:
        assert n in reg, n
    s = _scope(tmp_path)
    for n in PERSONA_COLLECTOR_NAMES:
        ok, _ = s.allows_persona_collector(n)
        assert not ok


def test_entity_type_alone_is_not_enough(tmp_path):
    """First key without the second must not open the gate."""
    s = _scope(tmp_path, entity_types_allowed="[Company, Persona]")
    ok, why = s.allows_persona_collector("github_intel")
    assert not ok
    assert "persona_collectors" in why


def test_allowlist_alone_is_not_enough(tmp_path):
    """Second key without the first must not open the gate either."""
    s = _scope(tmp_path, entity_types_allowed="[Company]",
               persona_collectors="[github_intel]")
    ok, why = s.allows_persona_collector("github_intel")
    assert not ok
    assert "entity_types_allowed" in why


def test_both_keys_open_the_gate(tmp_path):
    s = _scope(tmp_path, entity_types_allowed="[Company, Persona]",
               persona_collectors="[github_intel]")
    ok, _ = s.allows_persona_collector("github_intel")
    assert ok


def test_enabling_one_does_not_enable_the_rest(tmp_path):
    s = _scope(tmp_path, entity_types_allowed="[Persona]",
               persona_collectors="[gravatar]")
    assert s.allows_persona_collector("gravatar")[0]
    assert not s.allows_persona_collector("username_expand")[0]
    assert not s.allows_persona_collector("holehe")[0]


def test_username_enumeration_needs_its_own_third_key(tmp_path):
    s = _scope(tmp_path, entity_types_allowed="[Persona]",
               persona_collectors="[username_expand]")
    assert s.allows_persona_collector("username_expand")[0]
    assert s.allow_username_enumeration is False


def test_enumeration_flag_is_settable(tmp_path):
    s = _scope(tmp_path, entity_types_allowed="[Persona]",
               persona_collectors="[username_expand]",
               allow_username_enumeration="true")
    assert s.allow_username_enumeration is True


@pytest.mark.asyncio
async def test_username_expand_returns_nothing_without_the_flag(tmp_path):
    from attribution_graph import Identifier, IdKind

    from paytrace.collectors.persona import UsernameExpand

    s = _scope(tmp_path, entity_types_allowed="[Persona]",
               persona_collectors="[username_expand]")
    c = UsernameExpand(None, s)
    assert list(await c.collect(Identifier(IdKind.HANDLE, "github:someuser"))) == []
