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


def test_china_is_in_the_catalogue_and_is_not_shown_as_covered():
    """China was absent from the coverage map entirely.

    `attribution registries --jurisdiction CN` returned nothing, so a coverage
    report could say nothing at all about the second-largest source of
    corporate entities in the world. Worse, the one China collector the toolkit
    does implement -- CNINFO -- was not listed either, so it was invisible to
    the map while being live in a run.

    The authoritative register is NECIPS (gsxt.gov.cn, SAMR), it cannot be
    queried from here, and that has to be stated rather than discovered.
    """
    from paytrace.catalog import load_catalog

    cn = {r.name: r for r in load_catalog() if r.jurisdiction == "CN"}
    assert cn, "no China entry in the coverage map"

    necips = next((r for r in cn.values() if "NECIPS" in r.name), None)
    assert necips is not None, "the national register is not listed"
    assert necips.scope == "national"
    assert "gsxt.gov.cn" in necips.url
    # The barriers are the point of the entry.
    assert necips.requires_local_egress, "non-mainland blocking not recorded"
    assert necips.language.startswith("zh"), "Simplified-Chinese-only not recorded"
    assert necips.status == "manual lookup only"
    assert "uscc" in necips.yields, "the identifier the register is keyed on"
    for barrier in ("Real-name authentication", "November 2021",
                    "non-mainland", "not an absence in China"):
        assert barrier in necips.notes, f"barrier not stated: {barrier}"

    cninfo = next((r for r in cn.values() if "CNINFO" in r.name), None)
    assert cninfo is not None, "an implemented collector missing from the map"
    assert cninfo.collector == "cninfo_disclosure"
    assert cninfo.status == "implemented"
    # And it must not be mistakable for national coverage.
    assert cninfo.scope == "listed companies only"
    assert "almost nothing" in cninfo.notes


def test_the_cninfo_collector_points_at_the_register_that_covers_the_rest():
    """The docstring told the reader the opposite of the truth.

    It said unlisted entities "appear only in provincial AMR registries, which
    are not openly queryable". NECIPS is the national publication layer over
    exactly that data and is freely searchable by name or USCC -- so the
    sentence sent anyone reading it away from the one register that would have
    answered, and misattributed the obstacle while doing so.
    """
    from paytrace.collectors.lookups import CninfoDisclosure

    doc = CninfoDisclosure.__doc__ or ""
    assert "NECIPS" in doc, "the register that covers the rest is not named"
    assert "gsxt.gov.cn" in doc, "no URL for it"
    assert "publicly searchable" in doc, "the correction is not stated"
    # And the real obstacle, rather than "not openly queryable", which was both
    # wrong and the reason nobody went looking.
    assert "real-name authentication" in doc.lower()


def test_hong_kong_lists_the_open_data_route_beside_the_paid_one():
    """ICRIS is paid-per-search, and that was the only HK row.

    data.gov.hk publishes Companies Registry data for free, so a catalogue that
    offers only the paid route understates what can be checked without a
    budget. But it is an incremental feed rather than the register, and every
    one of those limits has to travel with it or it will be read as a company
    search.
    """
    from paytrace.catalog import load_catalog

    hk = [r for r in load_catalog() if r.jurisdiction == "HK"]
    assert len(hk) >= 2, "only one Hong Kong route listed"

    open_data = next(r for r in hk if "data.gov.hk" in r.url)
    assert open_data.access == "bulk"
    assert open_data.automatable, "a weekly CSV is automatable"
    assert open_data.status == "automatable, not implemented"
    # The licence is genuinely unstated upstream; claiming one would be worse
    # than recording that it is missing.
    assert "unspecified" in open_data.licence

    # The four limits, each verified against the published file itself.
    for limit in ("incremental feed", "2024-12-30", "BR number",
                  "Inland Revenue", "no previous name",
                  "no directors and no addresses"):
        assert limit in open_data.notes, f"limit not stated: {limit}"
    # It must not claim fields the file does not have.
    assert "directors" not in open_data.yields
    assert "previous_name" not in open_data.yields, \
        "the file dates a rename but never says what the old name was"
    assert "br_number" in open_data.yields
    assert "cr_number" not in open_data.yields, \
        "the BR number is not the CR number ICRIS is keyed on"

    icris = next(r for r in hk if "ICRIS" in r.name)
    assert "Paid-per-search" in icris.notes


def test_the_registry_listing_prints_every_paragraph_of_a_note(capsys):
    """`notes.splitlines()[0]` silently dropped the rest.

    These notes exist to carry the caveats that stop a reader misreading
    coverage. The NECIPS entry states four access barriers and the listing
    showed one, so the output read as "free name search, no public API" and
    omitted that the register cannot be reached from an ordinary vantage point
    at all -- a caveat recorded, stored, tested, and then not shown to the
    person it was written for.
    """
    from paytrace.cli import main

    main(["registries", "--jurisdiction", "CN"])
    out = capsys.readouterr().out
    assert "Real-name authentication" in out, "a later paragraph was dropped"
    assert "not an absence in China" in out, "the consequence was dropped"
    # Still readable: wrapped and indented under the entry, not one long line.
    longest = max(len(line) for line in out.splitlines())
    assert longest < 160, f"a {longest}-character line is not readable"


def test_the_coverage_table_shows_scope_beside_status():
    """Without scope, the status column misleads on exactly the hard cases.

    China sorts CNINFO above NECIPS, so the first CN row a skim-reader meets
    says "implemented" -- and CNINFO covers listed companies only, a tiny
    fraction of the register. The `scope` field already said so; it simply was
    not in the table. Same for a register that answers only to in-country
    requests: "manual lookup only" does not convey that it cannot be reached
    from here at all.
    """
    from paytrace.catalog import coverage_report

    report = coverage_report()
    assert "| Scope |" in report, "the table has no scope column"

    cninfo = next(ln for ln in report.splitlines() if "CNINFO" in ln)
    assert "listed companies only" in cninfo, (
        "an implemented listed-only collector reads as national coverage")

    necips = next(ln for ln in report.splitlines() if "NECIPS" in ln)
    assert "needs in-country egress" in necips, (
        "a register unreachable from here is not flagged in the table")

    hk = next(ln for ln in report.splitlines() if "data.gov.hk" in ln)
    assert "2024-12-30" in hk, "the feed's start date is its main limit"
