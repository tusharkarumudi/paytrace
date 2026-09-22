"""Robin ingest: extraction, correlation grouping, and the LLM ceiling."""

from attribution_graph import IdKind, Reliability, assess

from paytrace.robin_ingest import (
    from_robin,
    summarize,
    to_handle_observations,
)

FPR = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

INVESTIGATION = {
    "query": "ransomware affiliate kraken",
    "engine": "ahmia",
    "results": [
        {"link": f"http://{ONION}/thread/1",
         "content": (f"posted by kr4ken_x — PGP {FPR} — contact "
                     f"jabber: kraken@xmpp.example — btc bc1qw508d6qejxtdg4y5r3"
                     f"zarvary0c5xw7kv8f3t4")},
        {"link": f"http://{ONION}/thread/2",
         "content": f"vendor: kr4ken_x verified. mirror at {ONION}"},
    ],
    "summary": (f"The actor kr4ken_x appears to operate across several markets "
                f"and is likely the same person as another vendor. Key {FPR} "
                f"recurs throughout."),
}


def test_extracts_durable_identifiers():
    claims = from_robin(INVESTIGATION)
    kinds = {c.object.kind for c in claims if hasattr(c.object, "kind")}
    assert IdKind.PGP_FPR in kinds
    assert IdKind.HANDLE in kinds
    assert IdKind.DOMAIN in kinds


def test_one_page_is_one_correlation_group():
    """Ten identifiers on one page came from one retrieval."""
    claims = [c for c in from_robin(INVESTIGATION, include_llm_summary=False)
              if "/thread/1" in c.source_url]
    assert len(claims) > 3
    assert len({c.correlation_group for c in claims}) == 1


def test_llm_summary_is_capped_at_uncertain():
    """An LLM concluding two handles are one actor is inference, not observation."""
    llm = [c for c in from_robin(INVESTIGATION) if c.raw.get("llm_derived")]
    assert llm
    assert all(c.reliability is Reliability.UNCERTAIN for c in llm)


def test_entire_llm_summary_is_one_group():
    llm = [c for c in from_robin(INVESTIGATION) if c.raw.get("llm_derived")]
    assert len({c.correlation_group for c in llm}) == 1


def test_llm_claims_alone_cannot_attribute():
    """The whole point of the ceiling: a summary must not carry a finding."""
    llm = [c for c in from_robin(INVESTIGATION) if c.raw.get("llm_derived")]
    a = assess(llm, lambda i: 1)
    assert a.band.value in ("WEAK", "UNSUPPORTED")


def test_claims_are_marked_as_derived_not_captured():
    """Robin truncates and discards the body; the chain of custody must say so."""
    claims = from_robin(INVESTIGATION, include_llm_summary=False)
    assert all(c.raw.get("text_is_derived") for c in claims)


def test_onion_sources_are_flagged():
    claims = from_robin(INVESTIGATION, include_llm_summary=False)
    assert any(c.raw.get("onion") for c in claims)


def test_hex_false_positives_are_dropped():
    data = {"query": "x", "results": [
        {"link": "http://a.example", "content": "0000000000000000 ffffffffffffffff"}]}
    assert not [c for c in from_robin(data, include_llm_summary=False)
                if c.object.kind is IdKind.PGP_FPR]


def test_generic_handles_are_not_extracted():
    data = {"query": "x", "results": [
        {"link": "http://a.example", "content": "posted by anonymous, user: admin"}]}
    handles = [c.object.value for c in from_robin(data, include_llm_summary=False)
               if c.object.kind is IdKind.HANDLE]
    assert not handles


def test_scrape_multiple_output_shape_is_accepted():
    """Robin's scrape_multiple returns a bare {url: text} dict."""
    claims = from_robin({f"http://{ONION}/t": f"vendor: kr4ken_x PGP {FPR}"})
    assert claims


def test_handle_export_carries_page_level_links():
    """A shared key on the same page is what lifts handles above the floor."""
    rows = to_handle_observations(from_robin(INVESTIGATION), case_ref="C1")
    assert rows
    kraken = [r for r in rows if r["handle"] == "kr4ken_x"]
    assert kraken
    assert any(r.get("link_pgp") == FPR.lower() or r.get("link_pgp") == FPR
               for r in kraken)


def test_summary_states_the_evidentiary_limitation():
    out = summarize(from_robin(INVESTIGATION))
    assert "not preserved" in out and "cannot" in out


def test_empty_input_does_not_crash():
    assert from_robin({}) == []
    assert from_robin([]) == []
