"""Registry catalog integrity."""

from paytrace.catalog import coverage_report, load_catalog, query


def test_catalog_loads():
    assert len(load_catalog()) >= 25


def test_every_implemented_registry_names_a_real_collector():
    from paytrace.collectors import registry
    known = set(registry())
    for r in load_catalog():
        if r.collector:
            assert r.collector in known, f"{r.name} -> unknown collector {r.collector}"


def test_implemented_registries_are_automatable():
    for r in load_catalog():
        if r.collector:
            assert r.automatable, f"{r.name} has a collector but is marked manual"


def test_manual_registries_are_catalogued_not_hidden():
    """Knowing a registry exists and must be searched by hand is the point."""
    manual = [r for r in load_catalog() if not r.automatable]
    assert manual
    assert all(r.notes or r.url for r in manual)


def test_key_requiring_registries_declare_env_var():
    for r in load_catalog():
        if r.access == "api_key" and r.automatable:
            assert r.auth_env or r.collector, r.name


def test_jurisdiction_query_includes_global_sources():
    rows = query(jurisdiction="IN")
    assert any(r.jurisdiction == "IN" for r in rows)
    assert any(r.jurisdiction == "XX" for r in rows)


def test_coverage_report_renders():
    out = coverage_report()
    assert "Registry coverage" in out and "Manual entries are catalogued" in out


# ---- federated jurisdictions ------------------------------------------------ #

def test_uae_is_modelled_as_federated_not_as_one_register():
    """There is no UAE company register. Flattening seven authorities into one
    row produces confident false negatives."""
    from paytrace.catalog import load_catalog

    members = [r for r in load_catalog() if r.federation_of == "AE"]
    assert len(members) >= 6
    juris = {r.jurisdiction for r in members}
    assert {"AE-DIFC", "AE-ADGM", "AE-DMCC", "AE-DU"} <= juris


def test_the_ae_placeholder_states_there_is_no_national_register():
    from paytrace.catalog import load_catalog

    ae = [r for r in load_catalog()
          if r.jurisdiction == "AE" and not r.federation_of]
    assert len(ae) == 1, "the old lumped UAE row must not coexist with the federated model"
    assert "no national UAE company register" in ae[0].notes


def test_federated_warning_names_every_member():
    from paytrace.catalog import federated_warning

    w = federated_warning("AE")
    assert "no single national register" in w
    assert "AE-DIFC" in w and "AE-DMCC" in w
    assert "not evidence of anything" in w


def test_federated_warning_is_empty_for_unitary_jurisdictions():
    from paytrace.catalog import federated_warning

    assert federated_warning("GB") == ""


def test_registers_needing_local_egress_are_marked():
    """Some registers answer only to requests from inside the jurisdiction."""
    from paytrace.catalog import load_catalog

    local = [r for r in load_catalog() if r.requires_local_egress]
    assert local
    assert any(r.jurisdiction.startswith("AE") for r in local)


def test_non_english_registers_declare_their_language():
    """Automatable in principle and unusable in practice without the language."""
    from paytrace.catalog import load_catalog

    other = [r for r in load_catalog() if r.language != "en"]
    assert other
    assert any("ar" in r.language for r in other)


def test_member_directories_are_distinguished_from_statutory_registers():
    """DMCC lists companies that opted in. Absence proves nothing."""
    from paytrace.catalog import load_catalog

    dmcc = next(r for r in load_catalog() if r.jurisdiction == "AE-DMCC")
    assert "opted into being listed" in dmcc.notes
    assert "Absence proves nothing" in dmcc.notes


def test_opaque_jurisdictions_say_where_a_chain_terminates():
    from paytrace.catalog import load_catalog

    opaque = [r for r in load_catalog() if r.jurisdiction in ("BVI", "KY")]
    assert opaque
    assert any("beneficial" in r.notes.lower() or "no public" in r.notes.lower()
               for r in opaque)
