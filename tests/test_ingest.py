"""SpiderFoot and OpenCTI ingest."""


from attribution_graph import IdKind, Predicate, Reliability

from paytrace.ingest import (
    from_opencti_bundle,
    from_spiderfoot_csv,
    summarize,
)


def test_spiderfoot_csv_ingest(tmp_path):
    p = tmp_path / "scan1.csv"
    p.write_text(
        "Updated,Type,Module,Source,Source Type,F/P,Data\n"
        "2026-08-01 10:00:00,IP_ADDRESS,sfp_dnsresolve,a.example,DOMAIN_NAME,0,1.2.3.4\n"
        "2026-08-01 10:00:01,EMAILADDR,sfp_email,a.example,DOMAIN_NAME,0,ops@a.example\n"
        "2026-08-01 10:00:02,SIMILARDOMAIN,sfp_similar,a.example,DOMAIN_NAME,0,a-example.net\n"
        "2026-08-01 10:00:03,IP_ADDRESS,sfp_dnsresolve,a.example,DOMAIN_NAME,1,9.9.9.9\n"
    )
    claims = from_spiderfoot_csv(p)
    assert len(claims) == 3                       # false positive excluded
    assert all(c.collector.startswith("spiderfoot:") for c in claims)


def test_spiderfoot_false_positives_are_dropped(tmp_path):
    p = tmp_path / "s.csv"
    p.write_text("Updated,Type,Module,Source,Source Type,F/P,Data\n"
                 "2026-08-01,IP_ADDRESS,sfp_dns,a.example,DOMAIN_NAME,1,9.9.9.9\n")
    assert from_spiderfoot_csv(p) == []


def test_one_module_run_is_one_correlation_group(tmp_path):
    """A module emitting 50 events queried one API once."""
    rows = "".join(
        f"2026-08-01,CO_HOSTED_SITE,sfp_crossref,a.example,DOMAIN_NAME,0,site{i}.example\n"
        for i in range(50))
    p = tmp_path / "s.csv"
    p.write_text("Updated,Type,Module,Source,Source Type,F/P,Data\n" + rows)
    claims = from_spiderfoot_csv(p)
    assert len(claims) == 50
    assert len({c.correlation_group for c in claims}) == 1


def test_noisy_modules_are_downgraded(tmp_path):
    p = tmp_path / "s.csv"
    p.write_text(
        "Updated,Type,Module,Source,Source Type,F/P,Data\n"
        "2026-08-01,SIMILARDOMAIN,sfp_similar,a.example,DOMAIN_NAME,0,a-example.net\n"
        "2026-08-01,WEB_ANALYTICS_ID,sfp_pageinfo,a.example,DOMAIN_NAME,0,UA-1234567\n")
    by_type = {c.raw["sf_event_type"]: c.reliability for c in from_spiderfoot_csv(p)}
    assert by_type["SIMILARDOMAIN"] is Reliability.WEAK
    assert by_type["WEB_ANALYTICS_ID"] is Reliability.STRONG


def test_unknown_event_types_are_skipped_not_guessed(tmp_path):
    p = tmp_path / "s.csv"
    p.write_text("Updated,Type,Module,Source,Source Type,F/P,Data\n"
                 "2026-08-01,SOME_FUTURE_TYPE,sfp_x,a.example,DOMAIN_NAME,0,whatever\n")
    assert from_spiderfoot_csv(p) == []


def test_opencti_bundle_ingest():
    bundle = {
        "type": "bundle",
        "objects": [
            {"id": "domain-name--1", "type": "Domain-Name", "value": "a.example"},
            {"id": "ipv4-addr--1", "type": "IPv4-Addr", "value": "1.2.3.4"},
            {"id": "relationship--1", "type": "relationship",
             "relationship_type": "resolves-to", "source_ref": "domain-name--1",
             "target_ref": "ipv4-addr--1", "confidence": 90,
             "created_by_ref": "identity--report1",
             "created": "2026-08-01T10:00:00Z"},
        ],
    }
    claims = from_opencti_bundle(bundle)
    assert len(claims) == 1
    c = claims[0]
    assert c.subject.kind is IdKind.DOMAIN
    assert c.object.kind is IdKind.IP
    assert c.predicate is Predicate.CO_HOSTED
    assert c.reliability is Reliability.STRONG


def test_opencti_analyst_confidence_never_reaches_authoritative():
    """OpenCTI confidence is analyst-entered; 100 is not a registry assertion."""
    bundle = {"objects": [
        {"id": "d--1", "type": "Domain-Name", "value": "a.example"},
        {"id": "d--2", "type": "Domain-Name", "value": "b.example"},
        {"id": "r--1", "type": "relationship", "relationship_type": "related-to",
         "source_ref": "d--1", "target_ref": "d--2", "confidence": 100},
    ]}
    assert from_opencti_bundle(bundle)[0].reliability is not Reliability.AUTHORITATIVE


def test_opencti_groups_by_originating_report():
    """A report asserting 40 relationships is one source, not 40."""
    objs = [{"id": f"d--{i}", "type": "Domain-Name", "value": f"d{i}.example"}
            for i in range(6)]
    objs += [{"id": f"r--{i}", "type": "relationship", "relationship_type": "related-to",
              "source_ref": "d--0", "target_ref": f"d--{i}", "confidence": 70,
              "created_by_ref": "identity--report1"} for i in range(1, 6)]
    claims = from_opencti_bundle({"objects": objs})
    assert len(claims) == 5
    assert len({c.correlation_group for c in claims}) == 1


def test_relationships_to_objects_outside_bundle_are_skipped():
    bundle = {"objects": [
        {"id": "d--1", "type": "Domain-Name", "value": "a.example"},
        {"id": "r--1", "type": "relationship", "relationship_type": "related-to",
         "source_ref": "d--1", "target_ref": "missing--99"},
    ]}
    assert from_opencti_bundle(bundle) == []


def test_summarize_flags_group_concentration(tmp_path):
    rows = "".join(
        f"2026-08-01,CO_HOSTED_SITE,sfp_crossref,a.example,DOMAIN_NAME,0,s{i}.example\n"
        for i in range(20))
    p = tmp_path / "s.csv"
    p.write_text("Updated,Type,Module,Source,Source Type,F/P,Data\n" + rows)
    out = summarize(from_spiderfoot_csv(p))
    assert "correlation groups" in out and "one source once" in out
